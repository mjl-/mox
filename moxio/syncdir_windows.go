package moxio

// SyncDir opens a directory and syncs its contents to disk.
// SyncDir is a no-op on Windows.
func SyncDir(dir string) error {
	// todo: how to sync a directory on windows?
	return nil
}
