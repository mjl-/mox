# Types

Each Go type is stored in its own bucket, after its name. Only subbuckets are
created directly below a type bucket, no key/values. Two subbuckets are always
created: "records" for the data, "types" for the type definitions. Each index
is stored in a subbucket named "index." followed by the name. Unique and
non-unique indices use the same encoding.

# Type versions

Type definitions are stored in the "types" subbucket. The key is a 4 byte
uint32, a version as referenced from a data record. The value is a JSON-encoded
representation of the typeVersion struct.

When a new Go type or changed Go type is registered with a database, a new type
version is added to the "types" subbucket. Data is always inserted/updated with
the most recent type version. But the database may still hold data records
referencing older type versions. Bstore decodes a packed data record with the
referenced type version. For storage efficiency: the type version is reused for
many stored records, a self-describing format (like JSON) would duplicate the
field names in each stored record.

# Record storage

Primary keys of types are used as BoltDB keys and can be of bool, integer
types, strings or byte slices. Floats, time, struct, slice, map, binarymarshal
cannot be stored as primary key. Bools are stored as a single byte 0 or 1.
Integers are stored in their fixed width encoding (eg 4 bytes for 32 bit int).
Signed integers are stored so the fixed-width byte value is ordered for all
signed values, i.e. math.MinInt32 is stored as 4 bytes bigendian with value 0.
For strings and byte slices, only their bytes are stored.

The value stored with a BoltDB key starts with a uvarint "version" of the type.
This refers to a version in the "types" bucket. The primary key is not encoded
again in the data record itself. The remaining fields are space-efficiently
encoded.

After the uvarint version follow as many bytes to fit a bitmap for the direct
struct fields in the type description. Each bit indicates if the value is
nonzero and present in the value that follows. Only non-zero values take up
more space than the single bit and are stored consecutively after the fieldmap:

  - Pointers are stored as their non-pointer value. If the pointer is nil, it
    is zero in the fieldmap.
  - If the underlying type is an signed int or float, or unsigned int, then
    varint/uvarint encoding from encoding/binary is used.
  - If the underlying type is a string or []byte, uvarint count followed by the
    bytes.
  - If the underlying type is a bool, the value is always true and no
    additional data is present to represent the value. False is represented by
    the zero value marked in the fieldmap.
  - Slices use a uvarint for the number of elements, followed by a bitmap for
    nonzero values, followed by the encoded nonzero elements.
  - Maps use a uvariant for the number of key/value pairs, followed by a
    fieldmap for the values (the keys are always present), followed by each
    pair: key (always present), value (only if nonzero); key, value; etc.
  - If a type is an encoding.BinaryUnmarshaler and encoding.BinaryMarshaler,
    then its bytes are stored prefixed with its uvarint length.
  - If the type is a struct, its fields are encoded with a field map followed
    by the its nonzero field values.
  - Other types cannot be represented currently.

In a new type version, the type of a field can be changed as long as existing
records can be decoded into the new Go type. E.g. you can change an int32 into
a int64. You can only change an int64 into a int32 if all values you attempt to
read are small enough to fit in an int32. You cannot change between signed and
unsigned integer, or between string and []byte.

# Index storage

Indexes are stored in subbuckets, named starting with "index." followed by the
index name. Keys are a self-delimiting encodings of the fields that make up the
key, followed by the primary key for the "records" bucket. Values are always
empty in index buckets. For bool and integer types, the same fixed with
encoding as for primary keys in the "records" subbucket is used. Strings are
encoded by their bytes (no \0 allowed) followed by a delimiting \0. Unlike
primary keys, an index can cover a field with type time.Time. Times are encoded
with 8 byte seconds followed by the remaining 4 bytes nanoseconds.
