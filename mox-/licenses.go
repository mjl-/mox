package mox

import (
	"fmt"
	"io"
	"io/fs"
	"strings"
)

var LicensesFsys fs.FS

// LicensesWrite writes the licenses to dst.
func LicensesWrite(dst io.Writer) error {
	copyFile := func(p string) error {
		f, err := LicensesFsys.Open(p)
		if err != nil {
			return fmt.Errorf("open license file: %v", err)
		}
		if _, err := io.Copy(dst, f); err != nil {
			return fmt.Errorf("copy license file: %v", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close license file: %v", err)
		}
		return nil
	}

	if _, err := fmt.Fprintf(dst, "# github.com/mjl-/mox/LICENSE\n\n"); err != nil {
		return err
	}
	if err := copyFile("LICENSE.MIT"); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(dst, "\n\n# https://publicsuffix.org - Public Suffix List Mozilla\n\n"); err != nil {
		return err
	}
	if err := copyFile("LICENSE.MPLv2.0"); err != nil {
		return err
	}

	err := fs.WalkDir(LicensesFsys, "licenses", func(path string, d fs.DirEntry, err error) error {
		if !d.Type().IsRegular() {
			return nil
		}
		if _, err := fmt.Fprintf(dst, "\n\n# %s\n\n", strings.TrimPrefix(path, "licenses/")); err != nil {
			return err
		}
		return copyFile(path)
	})
	if err != nil {
		return fmt.Errorf("walk licenses: %v", err)
	}
	return nil
}
