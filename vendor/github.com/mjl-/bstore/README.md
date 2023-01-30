bstore is a database library for storing and quering Go struct data.

See https://pkg.go.dev/github.com/mjl-/bstore

MIT-licensed

# Comparison

Bstore is designed as a small, pure Go library that still provides most of the
common data consistency requirements for modest database use cases. Bstore aims
to make basic use of cgo-based libraries, such as sqlite, unnecessary.  Sqlite
is a great library, but Go applications that require cgo are hard to
cross-compile. With bstore, cross-compiling to most Go-supported platforms
stays trivial. Although bstore is much more limited in so many aspects than
sqlite, bstore also offers some advantages as well.

- Cross-compilation and reproducibility: Trivial with bstore due to pure Go,
  much harder with sqlite because of cgo.
- Code complexity: low with bstore (6k lines including comments/docs), high
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

# FAQ

Q: Is bstore an ORM?

A: No. The API for bstore may look like an ORM. But instead of mapping bstore
"queries" (function calls) to an SQL query string, bstore executes them
directly without converting to a query language.

Q: How does bstore store its data?

A bstore database is a single-file BoltDB database. BoltDB provides ACID
properties. Bstore uses a BoltDB "bucket" (key/value store) for each Go type
stored, with multiple subbuckets: one for type definitions, one for the actual
data, and one bucket per index. BoltDB stores data in a B+tree. See format.md
for details.
