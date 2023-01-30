# Sherpa

Sherpa is a Go library for creating a [sherpa API](https://www.ueber.net/who/mjl/sherpa/).

This library makes it trivial to export Go functions as a sherpa API with an http.Handler.

Your API will automatically be documented: github.com/mjl-/sherpadoc reads your Go source, and exports function and type comments as API documentation.

See the [documentation](https://godoc.org/github.com/mjl-/sherpa).


## Examples

A public sherpa API: https://www.sherpadoc.org/#https://www.sherpadoc.org/example/

That web application is [sherpaweb](https://github.com/mjl-/sherpaweb). It shows documentation for any sherpa API but also includes an API called Example for demo purposes.

[Ding](https://github.com/mjl-/ding/) is a more elaborate web application built with this library.


# About

Written by Mechiel Lukkien, mechiel@ueber.net.
Bug fixes, patches, comments are welcome.
MIT-licensed, see LICENSE.


# todo

- add a toggle for enabling calls by GET request. turn off by default for functions with parameters, people might be making requests with sensitive information in query strings...
- include a sherpaweb-like page that displays the documentation
- consider adding input & output validation and timestamp conversion to plain js lib
- consider using interfaces with functions (instead of direct structs) for server implementations. haven't needed it yet, but could be useful for mocking an api that you want to talk to.
- think about way to keep unknown fields. perhaps use a json lib that collects unknown keys in a map (which has to be added to the object for which you want to keep such keys).
- sherpajs: make a versionied, minified variant, with license line
- tool for comparing two jsons for compatibility, listing added sections/functions/types/fields
- be more helpful around errors that functions can generate. perhaps adding a mechanism for listing which errors can occur in the api json.
- handler: write tests
- client: write tests
