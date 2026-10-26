// Package transit talks to the OpenBao (or Vault) transit secrets engine over
// its HTTP API. Only encrypt, decrypt and token self-renewal are used, so the
// token this service holds needs nothing beyond those three capabilities.
package transit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Cipher encrypts and decrypts with a key that never leaves OpenBao.
type Cipher interface {
	Encrypt(ctx context.Context, plaintext []byte) (string, error)
	Decrypt(ctx context.Context, ciphertext string) ([]byte, error)
}

// TokenRenewer extends the lease of the token the client uses.
type TokenRenewer interface {
	RenewSelf(ctx context.Context) error
}

// TokenSource returns the current OpenBao token.
type TokenSource interface {
	Token() (string, error)
}

// ErrDecrypt is returned when OpenBao rejects a ciphertext: wrong key, tampered
// data or a ciphertext produced elsewhere.
var ErrDecrypt = errors.New("transit: ciphertext rejected")

// maxResponseBytes caps what is read from OpenBao; responses here are tiny.
const maxResponseBytes = 1 << 16

// Client is a minimal transit client bound to one mount and one key.
type Client struct {
	http    *http.Client
	baseURL string
	mount   string
	key     string
	tokens  TokenSource
}

// NewClient builds a client for https://host:port, the transit mount path and
// the key name. The http.Client carries the TLS configuration.
func NewClient(httpClient *http.Client, baseURL, mount, key string, tokens TokenSource) *Client {
	return &Client{
		http:    httpClient,
		baseURL: strings.TrimRight(baseURL, "/"),
		mount:   strings.Trim(mount, "/"),
		key:     key,
		tokens:  tokens,
	}
}

// Encrypt returns OpenBao's "vault:vN:..." ciphertext for plaintext.
func (c *Client) Encrypt(ctx context.Context, plaintext []byte) (string, error) {
	body := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}

	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}

	if _, err := c.call(ctx, http.MethodPost, c.keyPath("encrypt"), body, &out); err != nil {
		return "", err
	}

	if out.Data.Ciphertext == "" {
		return "", errors.New("transit: empty ciphertext in response")
	}

	return out.Data.Ciphertext, nil
}

// Decrypt returns the plaintext for a ciphertext produced by Encrypt.
func (c *Client) Decrypt(ctx context.Context, ciphertext string) ([]byte, error) {
	body := map[string]string{"ciphertext": ciphertext}

	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}

	status, err := c.call(ctx, http.MethodPost, c.keyPath("decrypt"), body, &out)
	if status == http.StatusBadRequest {
		return nil, ErrDecrypt
	}

	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(out.Data.Plaintext)
}

// RenewSelf renews the client's own token (periodic tokens live while renewed).
func (c *Client) RenewSelf(ctx context.Context) error {
	_, err := c.call(ctx, http.MethodPost, "/v1/auth/token/renew-self", map[string]string{}, nil)

	return err
}

func (c *Client) keyPath(op string) string {
	return "/v1/" + c.mount + "/" + op + "/" + url.PathEscape(c.key)
}

// call sends a JSON request and decodes a JSON response. It returns the HTTP
// status so callers can tell a rejected ciphertext from an outage. OpenBao's
// error bodies are not echoed: they can quote request fields.
func (c *Client) call(ctx context.Context, method, path string, in, out any) (int, error) {
	token, err := c.tokens.Token()
	if err != nil {
		return 0, fmt.Errorf("transit: token: %w", err)
	}

	payload, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}

	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("transit: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, err
	}

	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("transit: %s %s: HTTP %d", method, path, resp.StatusCode)
	}

	if out == nil {
		return resp.StatusCode, nil
	}

	return resp.StatusCode, json.Unmarshal(raw, out)
}
