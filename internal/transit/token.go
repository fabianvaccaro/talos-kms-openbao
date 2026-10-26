package transit

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// FileToken reads the token from a file on every call, so rotating the token
// only means replacing the file.
type FileToken struct {
	path string
}

// NewFileToken returns a TokenSource backed by path.
func NewFileToken(path string) *FileToken {
	return &FileToken{path: path}
}

// Token returns the trimmed file contents.
func (f *FileToken) Token() (string, error) {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}

	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("token file is empty")
	}

	return token, nil
}
