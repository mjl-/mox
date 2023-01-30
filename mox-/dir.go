package mox

import (
	"path/filepath"
)

// ConfigDirPath returns the path to "f". Either f itself when absolute, or
// interpreted relative to the directory of the current config file.
func ConfigDirPath(f string) string {
	return configDirPath(ConfigStaticPath, f)
}

// DataDirPath returns to the path to "f". Either f itself when absolute, or
// interpreted relative to the data directory from the currently active
// configuration.
func DataDirPath(f string) string {
	return dataDirPath(ConfigStaticPath, Conf.Static.DataDir, f)
}

// return f interpreted relative to the directory of the config dir. f is returned
// unchanged when absolute.
func configDirPath(configFile, f string) string {
	if filepath.IsAbs(f) {
		return f
	}
	return filepath.Join(filepath.Dir(configFile), f)
}

// return f interpreted relative to the data directory that is interpreted relative
// to the directory of the config dir. f is returned unchanged when absolute.
func dataDirPath(configFile, dataDir, f string) string {
	if filepath.IsAbs(f) {
		return f
	}
	return filepath.Join(configDirPath(configFile, dataDir), f)
}
