package kmsserver

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/siderolabs/kms-client/api/kms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/fabianvaccaro/talos-kms-openbao/internal/transit"
)

// gcmCipher stands in for OpenBao with real authenticated encryption, so
// tampering tests behave like the transit engine does.
type gcmCipher struct {
	aead cipher.AEAD
	down bool
}

func newGCM(t *testing.T) *gcmCipher {
	t.Helper()

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)

	return &gcmCipher{aead: aead}
}

func (g *gcmCipher) Encrypt(_ context.Context, pt []byte) (string, error) {
	if g.down {
		return "", errors.New("connection refused")
	}

	nonce := make([]byte, g.aead.NonceSize())
	_, _ = rand.Read(nonce)

	return "vault:v1:" + base64.StdEncoding.EncodeToString(g.aead.Seal(nonce, nonce, pt, nil)), nil
}

func (g *gcmCipher) Decrypt(_ context.Context, ct string) ([]byte, error) {
	if g.down {
		return nil, errors.New("connection refused")
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ct, "vault:v1:"))
	if err != nil || len(raw) < g.aead.NonceSize() {
		return nil, transit.ErrDecrypt
	}

	pt, err := g.aead.Open(nil, raw[:g.aead.NonceSize()], raw[g.aead.NonceSize():], nil)
	if err != nil {
		return nil, transit.ErrDecrypt
	}

	return pt, nil
}

const (
	nodeA = "4c4c4544-0042-3510-8051-b4c04f4d3232"
	nodeB = "11111111-2222-3333-4444-555555555555"
)

func newServer(t *testing.T) (*Server, *gcmCipher) {
	t.Helper()

	c := newGCM(t)

	return New(c, slog.New(slog.NewTextHandler(io.Discard, nil))), c
}

func passphrase() []byte {
	p := make([]byte, 32)
	_, _ = rand.Read(p)

	return p
}

func code(err error) codes.Code { return status.Code(err) }

func TestSealUnsealRoundTrip(t *testing.T) {
	s, _ := newServer(t)
	ctx := context.Background()
	p := passphrase()

	sealed, err := s.Seal(ctx, &kms.Request{NodeUuid: strings.ToUpper(nodeA), Data: p})
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(sealed.GetData(), p) {
		t.Fatal("sealed blob contains the passphrase")
	}

	got, err := s.Unseal(ctx, &kms.Request{NodeUuid: nodeA, Data: sealed.GetData()})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.GetData(), p) {
		t.Fatal("passphrase mismatch")
	}
}

func TestUnsealOtherNodeDenied(t *testing.T) {
	s, _ := newServer(t)
	ctx := context.Background()

	sealed, err := s.Seal(ctx, &kms.Request{NodeUuid: nodeA, Data: passphrase()})
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.Unseal(ctx, &kms.Request{NodeUuid: nodeB, Data: sealed.GetData()})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", code(err))
	}
}

func TestUnsealTamperedDenied(t *testing.T) {
	s, _ := newServer(t)
	ctx := context.Background()

	sealed, _ := s.Seal(ctx, &kms.Request{NodeUuid: nodeA, Data: passphrase()})
	blob := append([]byte(nil), sealed.GetData()...)
	blob[len(blob)-3] ^= 0x01

	if _, err := s.Unseal(ctx, &kms.Request{NodeUuid: nodeA, Data: blob}); code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", code(err))
	}
}

func TestUnsealForeignEnvelopeDenied(t *testing.T) {
	s, c := newServer(t)

	foreign, _ := c.Encrypt(context.Background(), passphrase())

	_, err := s.Unseal(context.Background(), &kms.Request{NodeUuid: nodeA, Data: []byte(foreign)})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", code(err))
	}
}

func TestInvalidInput(t *testing.T) {
	s, _ := newServer(t)
	ctx := context.Background()

	cases := map[string]func() error{
		"seal bad uuid": func() error {
			_, err := s.Seal(ctx, &kms.Request{NodeUuid: "../../etc", Data: passphrase()})

			return err
		},
		"seal short data": func() error {
			_, err := s.Seal(ctx, &kms.Request{NodeUuid: nodeA, Data: []byte("x")})

			return err
		},
		"unseal empty": func() error {
			_, err := s.Unseal(ctx, &kms.Request{NodeUuid: nodeA})

			return err
		},
		"unseal huge": func() error {
			_, err := s.Unseal(ctx, &kms.Request{NodeUuid: nodeA, Data: make([]byte, maxSealedBytes+1)})

			return err
		},
	}

	for name, call := range cases {
		if err := call(); code(err) != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", name, code(err))
		}
	}
}

func TestBackendDownIsUnavailable(t *testing.T) {
	s, c := newServer(t)
	ctx := context.Background()

	sealed, _ := s.Seal(ctx, &kms.Request{NodeUuid: nodeA, Data: passphrase()})
	c.down = true

	if _, err := s.Seal(ctx, &kms.Request{NodeUuid: nodeA, Data: passphrase()}); code(err) != codes.Unavailable {
		t.Fatalf("seal code = %v", code(err))
	}

	if _, err := s.Unseal(ctx, &kms.Request{NodeUuid: nodeA, Data: sealed.GetData()}); code(err) != codes.Unavailable {
		t.Fatalf("unseal code = %v", code(err))
	}
}
