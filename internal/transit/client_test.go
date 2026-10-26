package transit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testToken = "s.test-token"

// fakeBao mimics the transit endpoints: "encryption" is a reversible prefix,
// which is enough to test the HTTP contract (real crypto is OpenBao's job).
func fakeBao(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != testToken {
			w.WriteHeader(http.StatusForbidden)

			return
		}

		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)

		switch r.URL.Path {
		case "/v1/transit/encrypt/talos-kms":
			writeData(w, map[string]string{"ciphertext": "vault:v1:" + in["plaintext"]})
		case "/v1/transit/decrypt/talos-kms":
			pt, ok := strings.CutPrefix(in["ciphertext"], "vault:v1:")
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":["invalid ciphertext"]}`))

				return
			}

			writeData(w, map[string]string{"plaintext": pt})
		case "/v1/auth/token/renew-self":
			writeData(w, map[string]string{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func writeData(w http.ResponseWriter, data map[string]string) {
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func tokenFile(t *testing.T, value string) *FileToken {
	t.Helper()

	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	return NewFileToken(path)
}

func newTestClient(t *testing.T, token string) *Client {
	t.Helper()

	srv := fakeBao(t)
	t.Cleanup(srv.Close)

	return NewClient(srv.Client(), srv.URL+"/", "/transit/", "talos-kms", tokenFile(t, token))
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := newTestClient(t, testToken)
	ctx := context.Background()

	ct, err := c.Encrypt(ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	if want := "vault:v1:" + base64.StdEncoding.EncodeToString([]byte("secret")); ct != want {
		t.Fatalf("ciphertext = %q, want %q", ct, want)
	}

	pt, err := c.Decrypt(ctx, ct)
	if err != nil {
		t.Fatal(err)
	}

	if string(pt) != "secret" {
		t.Fatalf("plaintext = %q", pt)
	}
}

func TestDecryptRejectedCiphertext(t *testing.T) {
	c := newTestClient(t, testToken)

	if _, err := c.Decrypt(context.Background(), "garbage"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestWrongTokenIsAnOutageNotARejection(t *testing.T) {
	c := newTestClient(t, "s.wrong")

	_, err := c.Decrypt(context.Background(), "vault:v1:eA==")
	if err == nil || errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v, want a non-ErrDecrypt error", err)
	}

	if strings.Contains(err.Error(), "s.wrong") {
		t.Fatal("error leaks the token")
	}
}

func TestRenewSelf(t *testing.T) {
	if err := newTestClient(t, testToken).RenewSelf(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFileTokenErrors(t *testing.T) {
	if _, err := tokenFile(t, "  ").Token(); err == nil {
		t.Fatal("empty token accepted")
	}

	if _, err := NewFileToken(filepath.Join(t.TempDir(), "missing")).Token(); err == nil {
		t.Fatal("missing file accepted")
	}
}
