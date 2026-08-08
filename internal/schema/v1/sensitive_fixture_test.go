package v1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixtureSensitiveByteScan(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "reports", "v1")
	bad := []string{"user:password@", "secret-segment", "raw-query-value", "Authorization:", "Set-Cookie:", "BEGIN CERTIFICATE", "-----BEGIN", "docker-secret", "matcher-secret"}
	var scan func(string) error
	scan = func(dir string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				if err := scan(p); err != nil {
					return err
				}
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s := string(b)
			for _, x := range bad {
				if strings.Contains(s, x) {
					return &sensitiveFixtureError{p, x}
				}
			}
		}
		return nil
	}
	if err := scan(root); err != nil {
		t.Fatal(err)
	}
}

type sensitiveFixtureError struct{ path, token string }

func (e *sensitiveFixtureError) Error() string {
	return e.path + " contains forbidden token " + e.token
}
