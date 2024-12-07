// Package moxvar provides the version number of a mox build.
package moxvar

import (
	"runtime"
	"runtime/debug"
)

// Version is set at runtime based on the Go module used to build.
var Version string

// VersionBare does not add a "+modifications", goversion or other suffix to the version.
var VersionBare string

func init() {
	Version = "(devel)"
	VersionBare = "(devel)"

	defer func() {
		Version += "-" + runtime.Version()
	}()

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	Version = buildInfo.Main.Version
	VersionBare = buildInfo.Main.Version
	if Version == "(devel)" {
		var vcsRev, vcsMod string
		for _, setting := range buildInfo.Settings {
			if setting.Key == "vcs.revision" {
				vcsRev = setting.Value
			} else if setting.Key == "vcs.modified" {
				vcsMod = setting.Value
			}
		}
		if vcsRev == "" {
			return
		}
		Version = vcsRev
		VersionBare = vcsRev
		switch vcsMod {
		case "false":
		case "true":
			Version += "+modifications"
		default:
			Version += "+unknown"
		}
	}
}
