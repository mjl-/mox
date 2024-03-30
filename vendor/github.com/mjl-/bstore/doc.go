/*
Package bstore is an in-process database with serializable transactions
supporting referential/unique/nonzero constraints, (multikey) indices,
automatic schema management based on Go types and struct tags, and a query API.

Bstore a small, pure Go library that still provides most of the common data
consistency requirements for modest database use cases. Bstore aims to make
basic use of cgo-based libraries, such as sqlite, unnecessary.

Bstore implements autoincrementing primary keys, indices, default values,
enforcement of nonzero, unique and referential integrity constraints, automatic
schema updates and a query API for combining filters/sorting/limits. Queries
are planned and executed using indices for speed where possible.  Bstore works
with Go types: you typically don't have to write any (un)marshal code for your
types. Bstore is not an ORM, it plans and executes queries itself.

# Field types

Struct field types currently supported for storing, including pointers to these
types, but not pointers to pointers:

  - int (as int32), int8, int16, int32, int64
  - uint (as uint32), uint8, uint16, uint32, uint64
  - bool, float32, float64, string, []byte
  - Maps, with keys and values of any supported type, except keys with pointer types.
  - Slices and arrays, with elements of any supported type.
  - time.Time
  - Types that implement binary.MarshalBinary and binary.UnmarshalBinary, useful
    for struct types with state in private fields. Do not change the
    (Un)marshalBinary method in an incompatible way without a data migration.
  - Structs, with fields of any supported type.

Note: int and uint are stored as int32 and uint32, for compatibility of database
files between 32bit and 64bit systems. Where possible, use explicit (u)int32 or
(u)int64 types.

Cyclic types are supported, but cyclic data is not. Attempting to store cyclic
data will likely result in a stack overflow panic.

Anonymous struct fields are handled by taking in each of the anonymous struct's
fields as a type's own fields.  The named embedded type is not part of the type
schema, and with a Query it can currently only be used with UpdateField and
UpdateFields, not for filtering.

Bstore embraces the use of Go zero values. Use zero values, possibly pointers,
where you would use NULL values in SQL.

# Struct tags

The typical Go struct can be stored in the database. The first field of a
struct type is its primary key, must always be unique, and in case of an
integer type the insertion of a zero value automatically changes it to the next
sequence number by default.  Additional behaviour can be configured through
struct tag "bstore". The values are comma-separated.  Typically one word, but
some have multiple space-separated words:

  - "-" ignores the field entirely, not stored.
  - "name <fieldname>", use "fieldname" instead of the Go type field name.
  - "nonzero", enforces that field values are not the zero value.
  - "noauto", only valid for integer types, and only for the primary key. By
    default, an integer-typed primary key will automatically get a next value
    assigned on insert when it is 0. With noauto inserting a 0 value results in an
    error. For primary keys of other types inserting the zero value always results
    in an error.
  - "index" or "index <field1>+<field2>+<...> [<name>]", adds an index. In the
    first form, the index is on the field on which the tag is specified, and the
    index name is the same as the field name. In the second form multiple fields can
    be specified, and an optional name. The first field must be the field on which
    the tag is specified. The field names are +-separated. The default name for the
    second form is the same +-separated string but can be set explicitly with the
    second parameter. An index can only be set for basic integer types, bools, time
    and strings. A field of slice type can also have an index (but not a unique
    index, and only one slice field per index), allowing fast lookup of any single
    value in the slice with Query.FilterIn. Indices are automatically (re)created
    when registering a type. Fields with a pointer type cannot have an index.
    String values used in an index cannot contain a \0.
  - "unique" or "unique  <field1>+<field2>+<...> [<name>]", adds an index as with
    "index" and also enforces a unique constraint. For time.Time the timezone is
    ignored for the uniqueness check.
  - "ref <type>", enforces that the value exists as primary key for "type".
    Field types must match exactly, e.g. you cannot reference an int with an int64.
    An index is automatically created and maintained for fields with a foreign key,
    for efficiently checking that removed records in the referenced type are not in
    use. If the field has the zero value, the reference is not checked. If you
    require a valid reference, add "nonzero".
  - "default <value>", replaces a zero value with the specified value on record
    insert. Special value "now" is recognized for time.Time as the current time.
    Times are parsed as time.RFC3339 otherwise. Supported types: bool
    ("true"/"false"), integers, floats, strings. Value is not quoted and no escaping
    of special characters, like the comma that separates struct tag words, is
    possible.  Defaults are also replaced on fields in nested structs, slices
    and arrays, but not in maps.
  - "typename <name>", override name of the type. The name of the Go type is
    used by default. Can only be present on the first field (primary key).
    Useful for doing schema updates.

# Schema updates

Before using a Go type, you must register it for use with the open database by
passing a (possibly zero) value of that type to the Open or Register functions.
For each type, a type definition is stored in the database. If a type has an
updated definition since the previous database open, a new type definition is
added to the database automatically and any required modifications are made and
checked: Indexes (re)created, fields added/removed, new
nonzero/unique/reference constraints validated.

As a special case, you can change field types between pointer and non-pointer
types. With one exception: changing from pointer to non-pointer where the type
has a field that must be nonzero is not allowed. The on-disk encoding will not be
changed, and nil pointers will turn into zero values, and zero values into nil
pointers. Also see section Limitations about pointer types.

Because named embed structs are not part of the type definition, you can
wrap/unwrap fields into a embed/anonymous struct field. No new type definition
is created.

Some schema conversions are not allowed. In some cases due to architectural
limitations. In some cases because the constraint checks haven't been
implemented yet, or the parsing code does not yet know how to parse the old
on-disk values into the updated Go types. If you need a conversion that is not
supported, you will need to write a manual conversion, and you would have to
keep track whether the update has been executed.

Changes that are allowed:

  - From smaller to larger integer types (same signedness).
  - Removal of "noauto" on primary keys (always integer types). This updates the
    "next sequence" counter automatically to continue after the current maximum
    value.
  - Adding/removing/modifying an index, including a unique index. When a unique
    index is added, the current records are verified to be unique.
  - Adding/removing a reference. When a reference is added, the current records
    are verified to be valid references.
  - Add/remove a nonzero constraint. Existing records are verified.

Conversions that are not currently allowed, but may be in the future:

  - Signedness of integer types. With a one-time check that old values fit in the new
    type, this could be allowed in the future.
  - Conversions between basic types: strings, []byte, integers, floats, boolean.
    Checks would have to be added for some of these conversions. For example,
    from string to integer: the on-disk string values would have to be valid
    integers.
  - Types of primary keys cannot be changed, also not from one integer type to a
    wider integer type of same signedness.

# Bolt and storage

Bolt is used as underlying storage through the bbolt library. Bolt stores
key/values in a single file, allowing multiple/nested buckets (namespaces) in a
B+tree and provides ACID serializable transactions.  A single write transaction
can be active at a time, and one or more read-only transactions.  Do not start
a blocking read-only transaction in a goroutine while holding a writable
transaction or vice versa, this can cause deadlock.

Bolt returns Go values that are memory mapped to the database file.  This means
Bolt/bstore database files cannot be transferred between machines with
different endianness.  Bolt uses explicit widths for its types, so files can
be transferred between 32bit and 64bit machines of same endianness. While
Bolt returns read-only memory mapped byte slices, bstore only ever returns
parsed/copied regular writable Go values that require no special programmer
attention.

For each Go type opened for a database file, bstore ensures a Bolt bucket
exists with two subbuckets:

  - "types", with type descriptions of the stored records. Each time the database
    file is opened with a modified Go type (add/removed/modified
    field/type/bstore struct tag), a new type description is automatically added,
    identified by sequence number.
  - "records", containing all data, with the type's primary key as Bolt key,
    and the encoded remaining fields as value. The encoding starts with a
    reference to a type description.

For each index, another subbucket is created, its name starting with "index.".
The stored keys consist of the index fields followed by the primary key, and an
empty value. See format.md for details.

# Limitations

Bstore has limitations, not all of which are architectural so may be fixed in
the future.

Bstore does not implement the equivalent of SQL joins, aggregates, and many
other concepts.

Filtering/comparing/sorting on pointer fields is not allowed.  Pointer fields
cannot have a (unique) index. Use non-pointer values with the zero value as the
equivalent of a nil pointer.

The first field of a stored struct is always the primary key. Autoincrement is
only available for the primary key.

Bolt opens the database file with a lock. Only one process can have the
database open at a time.

An index stored on disk in Bolt can consume more disk space than other
database systems would: For each record, the indexed field(s) and primary key
are stored in full. Because bstore uses Bolt as key/value store, and doesn't
manage disk pages itself, it cannot as efficiently pack an index page with many
records.

Interface values cannot be stored. This would require storing the type along
with the value. Instead, use a type that is a BinaryMarshaler.

Values of builtin type "complex" cannot be stored.

Bstore inherits limitations from Bolt, see
https://pkg.go.dev/go.etcd.io/bbolt#readme-caveats-amp-limitations.

# Comparison with sqlite

Sqlite is a great library, but Go applications that require cgo are hard to
cross-compile. With bstore, cross-compiling to most Go-supported platforms
stays trivial (though not plan9, unfortunately). Although bstore is much more
limited in so many aspects than sqlite, bstore also offers some advantages as
well. Some points of comparison:

- Cross-compilation and reproducibility: Trivial with bstore due to pure Go,
  much harder with sqlite because of cgo.
- Code complexity: low with bstore (7k lines including comments/docs), high
  with sqlite.
- Query language: mostly-type-checked function calls in bstore, free-form query
  strings only checked at runtime with sqlite.
- Functionality: very limited with bstore, much more full-featured with sqlite.
- Schema management: mostly automatic based on Go type definitions in bstore,
  manual with ALTER statements in sqlite.
- Types and packing/parsing: automatic/transparent in bstore based on Go types
  (including maps, slices, structs and custom MarshalBinary encoding), versus
  manual scanning and parameter passing with sqlite with limited set of SQL
  types.
- Performance: low to good performance with bstore, high performance with
  sqlite.
- Database files: single file with bstore, several files with sqlite (due to
  WAL or journal files).
- Test coverage: decent coverage but limited real-world for bstore, versus
  extremely thoroughly tested and with enormous real-world use.
*/
package bstore
