https://pkg.go.dev/compress/flate from go1.24.0, with flate.NewReaderPartial
added: a Reader that returns data from blocks flushed with mode "partial
flush", without blocking on reading the next flate block. Without
NewReaderPartial, protocols that expect a response after writing a short
compressed request that was flushed in "partial flush" mode can get stuck.

Writes/flushes in "partial flush" mode are not implemented.

https://pkg.go.dev/github.com/mjl-/flate#NewReaderPartial

Also see https://github.com/golang/go/issues/31514
