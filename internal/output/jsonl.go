package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"ctfuzz/internal/result"
)

func WriteJSONL(path string, requests []result.Request, summaries []result.Summary) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}

	w := bufio.NewWriter(tmp)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	for _, req := range requests {
		if err := enc.Encode(req); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	for _, summary := range summaries {
		if err := enc.Encode(summary); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace output file: %w", err)
	}
	cleanup = false
	return nil
}
