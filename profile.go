package main

import (
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
)

func memprofile(mempath string) {
	if mempath == "" {
		return
	}

	f, err := os.Create(mempath)
	xcheckf(err, "creating memory profile")
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("closing memory profile: %v", err)
		}
	}()
	runtime.GC() // get up-to-date statistics
	err = pprof.WriteHeapProfile(f)
	xcheckf(err, "writing memory profile")
}

func profile(cpupath, mempath string) func() {
	if cpupath == "" {
		return func() {
			memprofile(mempath)
		}
	}

	f, err := os.Create(cpupath)
	xcheckf(err, "creating CPU profile")
	err = pprof.StartCPUProfile(f)
	xcheckf(err, "start CPU profile")
	return func() {
		pprof.StopCPUProfile()
		if err := f.Close(); err != nil {
			log.Printf("closing cpu profile: %v", err)
		}
		memprofile(mempath)
	}
}

func traceExecution(path string) func() {
	f, err := os.Create(path)
	xcheckf(err, "create trace file")
	trace.Start(f)
	return func() {
		trace.Stop()
		err := f.Close()
		xcheckf(err, "close trace file")
	}
}
