package bstore

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"reflect"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

/*
- todo: should thoroughly review guarantees, where some of the bstore struct tags are allowed (e.g. top-level fields vs deeper struct fields), check that all features work well when combined (cyclic types, embed structs, default values, nonzero checks, type equality, zero values with fieldmap, skipping values (hidden due to later typeversions) and having different type versions), write more extensive tests.
- todo: write tests for invalid (meta)data inside the boltdb buckets (not for invalid boltdb files). we should detect the error properly, give a reasonable message. we shouldn't panic (nil deref, out of bounds index, consume too much memory). typeVersions, records, indices.
- todo: add benchmarks. is there a standard dataset databases use for benchmarking?
- todo optimize: profile and see if we can optimize for some quick wins.
- todo: should we add a way for ad-hoc data manipulation? e.g. with sql-like queries, e.g. update, delete, insert; and export results of queries to csv.
- todo: should we have a function that returns records in a map? eg Map() that is like List() but maps a key to T (too bad we cannot have a type for the key!).
- todo: better error messages (ordering of description & error; mention typename, fields (path), field types and offending value & type more often)
- todo: should we add types for dates and numerics?
- todo: struct tag for enums? where we check if the values match.
*/

var (
	ErrAbsent       = errors.New("absent") // If a function can return an ErrAbsent, it can be compared directly, without errors.Is.
	ErrZero         = errors.New("must be nonzero")
	ErrUnique       = errors.New("not unique")
	ErrReference    = errors.New("referential inconsistency")
	ErrMultiple     = errors.New("multiple results")
	ErrSeq          = errors.New("highest autoincrement sequence value reached")
	ErrType         = errors.New("unknown/bad type")
	ErrIncompatible = errors.New("incompatible types")
	ErrFinished     = errors.New("query finished")
	ErrStore        = errors.New("internal/storage error") // E.g. when buckets disappear, possibly by external users of the underlying BoltDB database.
	ErrParam        = errors.New("bad parameters")
	ErrTxBotched    = errors.New("botched transaction") // Set on transactions after failed and aborted write operations.

	errTxClosed    = errors.New("transaction is closed")
	errNestedIndex = errors.New("struct tags index/unique only allowed at top-level structs")
)

var sanityChecks bool // Only enabled during tests.

// DB is a database storing Go struct values in an underlying bolt database.
// DB is safe for concurrent use, unlike a Tx or a Query.
type DB struct {
	bdb *bolt.DB

	// Read transaction take an rlock on types. Register can make changes and
	// needs a wlock.
	typesMutex sync.RWMutex
	types      map[reflect.Type]storeType
	typeNames  map[string]storeType // Type name to store type, for checking duplicates.

	statsMutex sync.Mutex
	stats      Stats
}

// Tx is a transaction on DB.
//
// A Tx is not safe for concurrent use.
type Tx struct {
	ctx context.Context // Check before starting operations, query next calls, and during foreach.
	err error           // If not nil, operations return this error. Set when write operations fail, e.g. insert with constraint violations.
	db  *DB             // If nil, this transaction is closed.
	btx *bolt.Tx

	bucketCache map[bucketKey]*bolt.Bucket

	stats Stats
}

// bucketKey represents a subbucket for a type.
type bucketKey struct {
	typeName string
	sub      string // Empty for top-level type bucket, otherwise "records", "types" or starting with "index.".
}

type index struct {
	Unique bool
	Name   string // Normally named after the field. But user can specify alternative name with "index" or "unique" struct tag with parameter.
	Fields []field

	tv *typeVersion
}

type storeType struct {
	Name    string       // Name of type as stored in database. Different from the current Go type name if the uses the "typename" struct tag.
	Type    reflect.Type // Type we parse into for new values.
	Current *typeVersion

	// Earlier schema versions. Older type versions can still be stored. We
	// prepare them for parsing into the reflect.Type. Some stored fields in
	// old versions may be ignored: when a later schema has removed the field,
	// that old stored field is considered deleted and will be ignored when
	// parsing.
	Versions map[uint32]*typeVersion
}

// note: when changing, possibly update func equal as well.
type typeVersion struct {
	Version       uint32              // First uvarint of a stored record references this version.
	OndiskVersion uint32              // Version of on-disk format. Currently always 1.
	Noauto        bool                // If true, the primary key is an int but opted out of autoincrement.
	Fields        []field             // Fields that we store. Embed/anonymous fields are kept separately in embedFields, and are not stored.
	Indices       map[string]*index   // By name of index.
	ReferencedBy  map[string]struct{} // Type names that reference this type. We require they are registered at the same time to maintain referential integrity.

	name         string
	referencedBy []*index            // Indexes (from other types) that reference this type.
	references   map[string]struct{} // Keys are the type names referenced. This is a summary for the references from Fields.
	embedFields  []embed             // Embed/anonymous fields, their values are stored through Fields, we keep them for setting values.

	fillPercent float64 // For "records" bucket. Set to 1 for append-only/mostly use as set with HintAppend, 0.5 otherwise.
}

// note: when changing, possibly update func equal as well.
// embed/anonymous fields are represented as type embed. The fields inside the embed type are of this type field.
type field struct {
	Name       string
	Type       fieldType
	Nonzero    bool     `json:",omitempty"`
	References []string `json:",omitempty"` // Referenced fields. Only for the top-level struct fields, not for nested structs.
	Default    string   `json:",omitempty"` // As specified in struct tag. Processed version is defaultValue.

	// If not the zero reflect.Value, set this value instead of a zero value on insert.
	// This is always a non-pointer value. Only set for the current typeVersion
	// linked to a Go type.
	defaultValue reflect.Value

	// Only set if this typeVersion will parse this field. We check
	// structField.Type for non-nil before parsing this field. We don't parse it
	// if this field is no longer in the type, or if it has been removed and
	// added again in later schema versions.
	structField reflect.StructField
	// Whether this field has been prepared for parsing into, i.e.
	// structField set if needed.
	prepared bool

	indices map[string]*index
}

// embed is for embed/anonymous fields. the fields inside are represented as a type field.
type embed struct {
	Name        string
	Type        fieldType
	structField reflect.StructField
}

type kind string

func (k kind) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(k))
}

func (k *kind) UnmarshalJSON(buf []byte) error {
	if string(buf) == "null" {
		return nil
	}
	if len(buf) > 0 && buf[0] == '"' {
		var s string
		if err := json.Unmarshal(buf, &s); err != nil {
			return fmt.Errorf("parsing fieldType.Kind string value %q: %v", buf, err)
		}
		nk, ok := kindsMap[s]
		if !ok {
			return fmt.Errorf("unknown fieldType.Kind value %q", s)
		}
		*k = nk
		return nil
	}

	// In ondiskVersion1, the kinds were integers, starting at 1.
	var i int
	if err := json.Unmarshal(buf, &i); err != nil {
		return fmt.Errorf("parsing fieldType.Kind int value %q: %v", buf, err)
	}
	if i <= 0 || i-1 >= len(kinds) {
		return fmt.Errorf("unknown fieldType.Kind value %d", i)
	}
	*k = kinds[i-1]
	return nil
}

const (
	kindBytes         kind = "bytes" // 1, etc
	kindBool          kind = "bool"
	kindInt           kind = "int"
	kindInt8          kind = "int8"
	kindInt16         kind = "int16"
	kindInt32         kind = "int32"
	kindInt64         kind = "int64"
	kindUint          kind = "uint"
	kindUint8         kind = "uint8"
	kindUint16        kind = "uint16"
	kindUint32        kind = "uint32"
	kindUint64        kind = "uint64"
	kindFloat32       kind = "float32"
	kindFloat64       kind = "float64"
	kindMap           kind = "map"
	kindSlice         kind = "slice"
	kindString        kind = "string"
	kindTime          kind = "time"
	kindBinaryMarshal kind = "binarymarshal"
	kindStruct        kind = "struct"
	kindArray         kind = "array"
)

// In ondiskVersion1, the kinds were integers, starting at 1.
// Do not change the order. Add new values at the end.
var kinds = []kind{
	kindBytes,
	kindBool,
	kindInt,
	kindInt8,
	kindInt16,
	kindInt32,
	kindInt64,
	kindUint,
	kindUint8,
	kindUint16,
	kindUint32,
	kindUint64,
	kindFloat32,
	kindFloat64,
	kindMap,
	kindSlice,
	kindString,
	kindTime,
	kindBinaryMarshal,
	kindStruct,
	kindArray,
}

func makeKindsMap() map[string]kind {
	m := map[string]kind{}
	for _, k := range kinds {
		m[string(k)] = k
	}
	return m
}

var kindsMap = makeKindsMap()

type fieldType struct {
	Ptr  bool `json:",omitempty"` // If type is a pointer.
	Kind kind // Type with possible Ptr deferenced.

	MapKey      *fieldType `json:",omitempty"`
	MapValue    *fieldType `json:",omitempty"`     // For kindMap.
	ListElem    *fieldType `json:"List,omitempty"` // For kindSlice and kindArray. Named List in JSON for compatibility.
	ArrayLength int        `json:",omitempty"`     // For kindArray.

	// For kindStruct, the fields of the struct. Only set for the first use of the type
	// within a registered type. Code dealing with fields should use structFields
	// (below) most of the time instead, it has the effective fields after resolving
	// the type reference.
	// Named "Fields" in JSON to stay compatible with ondiskVersion1, named
	// DefinitionFields in Go for clarity.
	DefinitionFields []field `json:"Fields,omitempty"`

	// For struct types, the sequence number of this type (within the registered type).
	// Needed for supporting cyclic types.  Each struct type is assigned the next
	// sequence number. The registered type implicitly has sequence 1. If positive,
	// this defines a type (i.e. when it is first encountered analyzing fields
	// depth-first). If negative, it references the type with positive seq (when a
	// field is encountered of a type that was seen before). New since ondiskVersion2,
	// structs in ondiskVersion1 will have zero value 0.
	FieldsTypeSeq int `json:",omitempty"`

	// Fields after taking cyclic types into account. Set when registering/loading a
	// type. Not stored on disk because of potential cyclic data.
	structFields []field
}

// Options configure how a database should be opened or initialized.
type Options struct {
	Timeout        time.Duration // Abort if opening DB takes longer than Timeout. If not set, the deadline from the context is used.
	Perm           fs.FileMode   // Permissions for new file if created. If zero, 0600 is used.
	MustExist      bool          // Before opening, check that file exists. If not, io/fs.ErrNotExist is returned.
	RegisterLogger *slog.Logger  // For debug logging about schema upgrades.
}

// Open opens a bstore database and registers types by calling Register.
//
// If the file does not exist, a new database file is created, unless opts has
// MustExist set. Files are created with permission 0600, or with Perm from
// Options if nonzero.
//
// Only one DB instance can be open for a file at a time. Use opts.Timeout to
// specify a timeout during open to prevent indefinite blocking.
//
// The context is used for opening and initializing the database, not for further
// operations. If the context is canceled while waiting on the database file lock,
// the operation is not aborted other than when the deadline/timeout is reached.
//
// See function Register for checks for changed/unchanged schema during open
// based on environment variable "bstore_schema_check".
func Open(ctx context.Context, path string, opts *Options, typeValues ...any) (*DB, error) {
	var bopts *bolt.Options
	if opts != nil && opts.Timeout > 0 {
		bopts = &bolt.Options{Timeout: opts.Timeout}
	} else if end, ok := ctx.Deadline(); ok {
		bopts = &bolt.Options{Timeout: time.Until(end)}
	}
	var mode fs.FileMode = 0600
	if opts != nil && opts.Perm != 0 {
		mode = opts.Perm
	}
	if opts != nil && opts.MustExist {
		if _, err := os.Stat(path); err != nil {
			return nil, err
		}
	}
	bdb, err := bolt.Open(path, mode, bopts)
	if err != nil {
		return nil, err
	}

	typeNames := map[string]storeType{}
	types := map[reflect.Type]storeType{}
	db := &DB{bdb: bdb, typeNames: typeNames, types: types}
	var log *slog.Logger
	if opts != nil {
		log = opts.RegisterLogger
	}
	if log == nil {
		log = slog.New(discardHandler{})
	} else {
		log = log.With("dbpath", path)
	}
	if err := db.register(ctx, log, typeValues...); err != nil {
		bdb.Close()
		return nil, err
	}
	return db, nil
}

// Close closes the underlying database.
func (db *DB) Close() error {
	return db.bdb.Close()
}

// Stats returns usage statistics for the lifetime of DB.  Stats are tracked
// first in a Query or a Tx. Stats from a Query are propagated to its Tx when
// the Query finishes. Stats from a Tx are propagated to its DB when the
// transaction ends.
func (db *DB) Stats() Stats {
	db.statsMutex.Lock()
	defer db.statsMutex.Unlock()
	return db.stats
}

// Stats returns usage statistics for this transaction.
// When a transaction is rolled back or committed, its statistics are copied
// into its DB.
func (tx *Tx) Stats() Stats {
	return tx.stats
}

// WriteTo writes the entire database to w, not including changes made during this transaction.
func (tx *Tx) WriteTo(w io.Writer) (n int64, err error) {
	if err := tx.error(); err != nil {
		return 0, err
	}
	return tx.btx.WriteTo(w)
}

// return a bucket through cache.
func (tx *Tx) bucket(bk bucketKey) (*bolt.Bucket, error) {
	if tx.bucketCache == nil {
		tx.bucketCache = map[bucketKey]*bolt.Bucket{}
	}
	b := tx.bucketCache[bk]
	if b != nil {
		return b, nil
	}
	top := tx.bucketCache[bucketKey{bk.typeName, ""}]
	if top == nil {
		tx.stats.Bucket.Get++
		top = tx.btx.Bucket([]byte(bk.typeName))
		if top == nil {
			return nil, fmt.Errorf("%w: missing bucket for type %q", ErrStore, bk.typeName)
		}
		tx.bucketCache[bucketKey{bk.typeName, ""}] = top
	}
	if bk.sub == "" {
		return top, nil
	}

	tx.stats.Bucket.Get++
	b = top.Bucket([]byte(bk.sub))
	if b == nil {
		return nil, fmt.Errorf("%w: missing bucket %q for type %q", ErrStore, bk.sub, bk.typeName)
	}
	tx.bucketCache[bk] = b
	return b, nil
}

func (tx *Tx) typeBucket(typeName string) (*bolt.Bucket, error) {
	return tx.bucket(bucketKey{typeName, ""})
}

func (tx *Tx) recordsBucket(typeName string, fillPercent float64) (*bolt.Bucket, error) {
	b, err := tx.bucket(bucketKey{typeName, "records"})
	if err != nil {
		return nil, err
	}
	b.FillPercent = fillPercent
	return b, nil
}

func (tx *Tx) indexBucket(idx *index) (*bolt.Bucket, error) {
	return tx.bucket(bucketKey{idx.tv.name, "index." + idx.Name})
}

// Drop removes a type and its data from the database.
// If the type is currently registered, it is unregistered and no longer available.
// If a type is still referenced by another type, eg through a "ref" struct tag,
// ErrReference is returned.
// If the type does not exist, ErrAbsent is returned.
func (db *DB) Drop(ctx context.Context, name string) error {
	var st storeType
	var ok bool
	err := db.Write(ctx, func(tx *Tx) error {
		tx.stats.Bucket.Get++
		if tx.btx.Bucket([]byte(name)) == nil {
			return ErrAbsent
		}

		st, ok = db.typeNames[name]
		if ok && len(st.Current.referencedBy) > 0 {
			return fmt.Errorf("%w: type is still referenced", ErrReference)
		}

		tx.stats.Bucket.Delete++
		return tx.btx.DeleteBucket([]byte(name))
	})
	if err != nil {
		return err
	}

	if ok {
		for ref := range st.Current.references {
			var n []*index
			for _, idx := range db.typeNames[ref].Current.referencedBy {
				if idx.tv != st.Current {
					n = append(n, idx)
				}
			}
			db.typeNames[ref].Current.referencedBy = n
		}
		delete(db.typeNames, name)
		delete(db.types, st.Type)
	}
	return nil
}

// Delete calls Delete on a new writable Tx.
func (db *DB) Delete(ctx context.Context, values ...any) error {
	return db.Write(ctx, func(tx *Tx) error {
		return tx.Delete(values...)
	})
}

// Get calls Get on a new read-only Tx.
func (db *DB) Get(ctx context.Context, values ...any) error {
	return db.Read(ctx, func(tx *Tx) error {
		return tx.Get(values...)
	})
}

// Insert calls Insert on a new writable Tx.
func (db *DB) Insert(ctx context.Context, values ...any) error {
	return db.Write(ctx, func(tx *Tx) error {
		return tx.Insert(values...)
	})
}

// Update calls Update on a new writable Tx.
func (db *DB) Update(ctx context.Context, values ...any) error {
	return db.Write(ctx, func(tx *Tx) error {
		return tx.Update(values...)
	})
}

var typeKinds = map[reflect.Kind]kind{
	reflect.Bool:    kindBool,
	reflect.Int:     kindInt,
	reflect.Int8:    kindInt8,
	reflect.Int16:   kindInt16,
	reflect.Int32:   kindInt32,
	reflect.Int64:   kindInt64,
	reflect.Uint:    kindUint,
	reflect.Uint8:   kindUint8,
	reflect.Uint16:  kindUint16,
	reflect.Uint32:  kindUint32,
	reflect.Uint64:  kindUint64,
	reflect.Float32: kindFloat32,
	reflect.Float64: kindFloat64,
	reflect.Map:     kindMap,
	reflect.Slice:   kindSlice,
	reflect.String:  kindString,
	reflect.Array:   kindArray,
}

func typeKind(t reflect.Type) (kind, error) {
	if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
		return kindBytes, nil
	}

	k, ok := typeKinds[t.Kind()]
	if ok {
		return k, nil
	}

	if t == reflect.TypeOf(zerotime) {
		return kindTime, nil
	}

	if reflect.PointerTo(t).AssignableTo(reflect.TypeOf((*encoding.BinaryMarshaler)(nil)).Elem()) {
		return kindBinaryMarshal, nil
	}

	if t.Kind() == reflect.Struct {
		return kindStruct, nil
	}
	if t.Kind() == reflect.Ptr {
		return "", fmt.Errorf("%w: pointer to pointers not supported: %v", ErrType, t.Elem())
	}
	return "", fmt.Errorf("%w: unsupported type %v", ErrType, t)
}

func typeName(t reflect.Type) (string, error) {
	tags, err := newStoreTags(t.Field(0).Tag.Get("bstore"), true)
	if err != nil {
		return "", err
	}
	if name, err := tags.Get("typename"); err != nil {
		return "", err
	} else if name != "" {
		return name, nil
	}
	return t.Name(), nil
}

// Get value for a key. For insert a next sequence may be generated for the
// primary key.
func (tv typeVersion) keyValue(tx *Tx, rv reflect.Value, insert bool, rb *bolt.Bucket) ([]byte, reflect.Value, bool, error) {
	f := tv.Fields[0]
	krv := rv.FieldByIndex(f.structField.Index)
	var seq bool
	if krv.IsZero() {
		if !insert {
			return nil, reflect.Value{}, seq, fmt.Errorf("%w: primary key can not be zero value", ErrParam)
		}
		if tv.Noauto {
			return nil, reflect.Value{}, seq, fmt.Errorf("%w: primary key cannot be zero value without autoincrement", ErrParam)
		}
		id, err := rb.NextSequence()
		if err != nil {
			return nil, reflect.Value{}, seq, fmt.Errorf("next primary key: %w", err)
		}
		switch f.Type.Kind {
		case kindInt, kindInt8, kindInt16, kindInt32, kindInt64:
			if krv.OverflowInt(int64(id)) {
				return nil, reflect.Value{}, seq, fmt.Errorf("%w: next primary key sequence does not fit in type", ErrSeq)
			}
			krv.SetInt(int64(id))
		case kindUint, kindUint8, kindUint16, kindUint32, kindUint64:
			if krv.OverflowUint(id) {
				return nil, reflect.Value{}, seq, fmt.Errorf("%w: next primary key sequence does not fit in type", ErrSeq)
			}
			krv.SetUint(id)
		default:
			// todo: should check this during register.
			return nil, reflect.Value{}, seq, fmt.Errorf("%w: unsupported autoincrement primary key type %v", ErrZero, f.Type.Kind)
		}
		seq = true
	} else if !tv.Noauto && insert {
		// We let user insert their own ID for our own autoincrement
		// PK. But we update the internal next sequence if the users's
		// PK is highest yet, so a future autoincrement insert will succeed.
		switch f.Type.Kind {
		case kindInt, kindInt8, kindInt16, kindInt32, kindInt64:
			v := krv.Int()
			if v > 0 && uint64(v) > rb.Sequence() {
				if err := rb.SetSequence(uint64(v)); err != nil {
					return nil, reflect.Value{}, seq, fmt.Errorf("%w: updating sequence: %s", ErrStore, err)
				}
			}
		case kindUint, kindUint8, kindUint16, kindUint32, kindUint64:
			v := krv.Uint()
			if v > rb.Sequence() {
				if err := rb.SetSequence(v); err != nil {
					return nil, reflect.Value{}, seq, fmt.Errorf("%w: updating sequence: %s", ErrStore, err)
				}
			}
		}
	}

	k, err := packPK(krv)
	if err != nil {
		return nil, reflect.Value{}, seq, err
	}
	if seq {
		tx.stats.Records.Get++
		if rb.Get(k) != nil {
			return nil, reflect.Value{}, seq, fmt.Errorf("%w: internal error: next sequence value is already present", ErrUnique)
		}
	}
	return k, krv, seq, err
}

// Read calls function fn with a new read-only transaction, ensuring transaction rollback.
func (db *DB) Read(ctx context.Context, fn func(*Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	db.typesMutex.RLock()
	defer db.typesMutex.RUnlock()
	return db.bdb.View(func(btx *bolt.Tx) error {
		tx := &Tx{ctx: ctx, db: db, btx: btx}
		tx.stats.Reads++
		defer tx.addStats()
		if err := fn(tx); err != nil {
			return err
		}
		return tx.err
	})
}

// Write calls function fn with a new read-write transaction. If fn returns
// nil, the transaction is committed. Otherwise the transaction is rolled back.
func (db *DB) Write(ctx context.Context, fn func(*Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	db.typesMutex.RLock()
	defer db.typesMutex.RUnlock()
	return db.bdb.Update(func(btx *bolt.Tx) error {
		tx := &Tx{ctx: ctx, db: db, btx: btx}
		tx.stats.Writes++
		defer tx.addStats()
		if err := fn(tx); err != nil {
			return err
		}
		return tx.err
	})
}

// lookup storeType based on name of rt.
func (db *DB) storeType(rt reflect.Type) (storeType, error) {
	st, ok := db.types[rt]
	if !ok {
		return storeType{}, fmt.Errorf("%w: %v", ErrType, rt)
	}
	return st, nil
}

// HintAppend sets a hint whether changes to the types indicated by each struct
// from values is (mostly) append-only.
//
// This currently sets the BoltDB bucket FillPercentage to 1 for efficient use
// of storage space.
func (db *DB) HintAppend(append bool, values ...any) error {
	db.typesMutex.Lock()
	defer db.typesMutex.Unlock()
	for _, v := range values {
		t := reflect.TypeOf(v)
		st, err := db.storeType(t)
		if err != nil {
			return err
		}
		if append {
			st.Current.fillPercent = 1.0
		} else {
			st.Current.fillPercent = 0.5
		}
	}
	return nil
}
