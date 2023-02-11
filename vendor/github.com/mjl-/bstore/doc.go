/*
Package bstore is a database library for storing and querying Go struct data.

Bstore is designed as a small, pure Go library that still provides most of
the common data consistency requirements for modest database use cases. Bstore
aims to make basic use of cgo-based libraries, such as sqlite, unnecessary.

Bstore implements autoincrementing primary keys, indices, default values,
enforcement of nonzero, unique and referential integrity constraints, automatic
schema updates and a query API for combining filters/sorting/limits. Queries
are planned and executed using indices for fast execution where possible.
Bstores is designed with the Go type system in mind: you typically don't have to
write any (un)marshal code for your types.

# Field types

Struct field types currently supported for storing, including pointers to these
types, but not pointers to pointers:

  - int (as int32), int8, int16, int32, int64
  - uint (as uint32), uint8, uint16, uint32, uint64
  - bool, float32, float64, string, []byte
  - Maps, with keys and values of any supported type, except keys with pointer types.
  - Slices, with elements of any supported type.
  - time.Time
  - Types that implement binary.MarshalBinary and binary.UnmarshalBinary, useful
    for struct types with state in private fields. Do not change the
    (Un)marshalBinary method in an incompatible way without a data migration.
  - Structs, with fields of any supported type.

Note: int and uint are stored as int32 and uint32, for compatibility of database
files between 32bit and 64bit systems. Where possible, use explicit (u)int32 or
(u)int64 types.

Embedded structs are handled by storing the individual fields of the embedded
struct. The named embedded type is not part of the type schema, and can
currently only be used with UpdateField and UpdateFields, not for filtering.

Bstore embraces the use of Go zero values. Use zero values, possibly pointers,
where you would use NULL values in SQL.

Types that have not yet been implemented: interface values, (fixed length) arrays,
complex numbers.

# Struct tags

The typical Go struct can be stored in the database. The first field of a
struct type is its primary key, and must always be unique. Additional behaviour
can be configured through struct tag "bstore". The values are comma-separated.
Typically one word, but some have multiple space-separated words:

  - "-" ignores the field entirely.
  - "name <fieldname>", use "fieldname" instead of the Go type field name.
  - "nonzero", enforces that field values are not the zero value.
  - "noauto", only valid for integer types, and only for the primary key. By
    default, an integer-typed primary key will automatically get a next value
    assigned on insert when it is 0. With noauto inserting a 0 value results in an
    error. For primary keys of other types inserting the zero value always results
    in an error.
  - "index" or "index <field1+field2+...> [<name>]", adds an index. In the first
    form, the index is on the field on which the tag is specified, and the index
    name is the same as the field name. In the second form multiple fields can be
    specified, and an optional name. The first field must be the field on which
    the tag is specified. The field names are +-separated. The default name for
    the second form is the same +-separated string but can be set explicitly to
    the second parameter. An index can only be set for basic integer types, bools,
    time and strings. Indices are automatically (re)created when registering a
    type.
  - "unique" or "unique  <field1+field2+...> [<name>]", adds an index as with
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
    possible.  Defaults are also replaced on fields in nested structs and
    slices, but not in maps.
  - "typename <name>", override name of the type. The name of the Go type is
    used by default. Can only be present on the first field (primary key).
    Useful for doing schema updates.

# Schema updates

Before using a Go type, you must register it for use with the open database by
passing a (zero) value of that type to the Open or Register functions. For each
type, a type definition is stored in the database. If a type has an updated
definition since the previous database open, a new type definition is added to
the database automatically and any required modifications are made: Indexes
(re)created, fields added/removed, new nonzero/unique/reference constraints
validated.

If data/types cannot be updated automatically (e.g. converting an int field into
a string field), custom data migration code is needed. You may have to keep
track of a data/schema version.

As a special case, you can switch field types between pointer and non-pointer
types. With one exception: changing from pointer to non-pointer where the type
has a field that must be nonzero is not allowed. The on-disk encoding will not be
changed, and nil pointers will turn into zero values, and zero values into nil
pointers. Also see section Limitations about pointer types.

Because named embed structs are not part of the type definition, you can
wrap/unwrap fields into a embed/anonymous struct field. No new type definition
is created.

# BoltDB

BoltDB is used as underlying storage. Bolt provides ACID transactions, storing
its data in a B+tree.  Only a single write transaction can be active at a time,
but otherwise multiple read-only transactions can be active. Do not start a
blocking read-only transaction while holding a writable transaction or vice
versa, this will cause deadlock.

Bolt uses Go types that are memory mapped  to the database file. This means bolt
database files cannot be transferred between machines with different endianness.
Bolt uses explicit widths for its types, so files can be transferred between
32bit and 64bit machines of same endianness.

# Limitations

Bstore does not implement the equivalent of SQL joins, aggregates, and many
other concepts.

Filtering/comparing/sorting on pointer fields is not currently allowed.  Pointer
fields cannot have a (unique) index due to the current index format.  Using zero
values is recommended instead for now.

Integer field types can be expanded to wider types, but not to a different
signedness or a smaller integer (fewer bits). The primary key of a type cannot
currently be changed.

The first field of a struct is always the primary key. Types requires an
explicit primary key. Autoincrement is only available for the primary key.
*/
package bstore
