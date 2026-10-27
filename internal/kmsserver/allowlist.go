package kmsserver

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// NodePolicy decides which node UUIDs may seal and unseal.
type NodePolicy interface {
	Allowed(uuid string) (bool, error)
}

// AllowAll admits every node; used when no allowlist is configured.
type AllowAll struct{}

// Allowed always returns true.
func (AllowAll) Allowed(string) (bool, error) { return true, nil }

// FileAllowlist admits the UUIDs listed in a file, one per line; blank lines
// and lines starting with # are ignored. The file is read on every call, so
// enrolling a node is just editing the file (requests are rare: one per boot).
type FileAllowlist struct {
	path string
}

// NewFileAllowlist returns a NodePolicy backed by path.
func NewFileAllowlist(path string) *FileAllowlist {
	return &FileAllowlist{path: path}
}

// Allowed reports whether uuid (already normalized) is listed.
func (f *FileAllowlist) Allowed(uuid string) (bool, error) {
	file, err := os.Open(f.path)
	if err != nil {
		return false, fmt.Errorf("open allowlist: %w", err)
	}
	defer file.Close() //nolint:errcheck

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := normalizeUUID(strings.Fields(line)[0])
		if err == nil && entry == uuid {
			return true, nil
		}
	}

	return false, scanner.Err()
}
