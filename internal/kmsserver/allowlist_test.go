package kmsserver

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/siderolabs/kms-client/api/kms"
	"google.golang.org/grpc/codes"
)

func writeAllowlist(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "allowed-nodes")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestFileAllowlistParsing(t *testing.T) {
	path := writeAllowlist(t, "# test nodes\n\n  "+strings.ToUpper(nodeA)+"  talos-test-01\n")
	list := NewFileAllowlist(path)

	if ok, err := list.Allowed(nodeA); err != nil || !ok {
		t.Fatalf("nodeA: ok=%v err=%v", ok, err)
	}

	if ok, err := list.Allowed(nodeB); err != nil || ok {
		t.Fatalf("nodeB: ok=%v err=%v", ok, err)
	}
}

func TestFileAllowlistMissingFileFailsClosed(t *testing.T) {
	ok, err := NewFileAllowlist(filepath.Join(t.TempDir(), "missing")).Allowed(nodeA)
	if ok || err == nil {
		t.Fatalf("ok=%v err=%v, want denied with error", ok, err)
	}
}

func newServerWithPolicy(t *testing.T, policy NodePolicy) *Server {
	t.Helper()

	return New(newGCM(t), policy, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestServerEnforcesAllowlist(t *testing.T) {
	s := newServerWithPolicy(t, NewFileAllowlist(writeAllowlist(t, nodeA+"\n")))
	ctx := context.Background()

	sealed, err := s.Seal(ctx, &kms.Request{NodeUuid: nodeA, Data: passphrase()})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Seal(ctx, &kms.Request{NodeUuid: nodeB, Data: passphrase()}); code(err) != codes.PermissionDenied {
		t.Fatalf("seal unknown node: code = %v", code(err))
	}

	if _, err := s.Unseal(ctx, &kms.Request{NodeUuid: nodeB, Data: sealed.GetData()}); code(err) != codes.PermissionDenied {
		t.Fatalf("unseal unknown node: code = %v", code(err))
	}

	if _, err := s.Unseal(ctx, &kms.Request{NodeUuid: nodeA, Data: sealed.GetData()}); err != nil {
		t.Fatalf("unseal enrolled node: %v", err)
	}
}

func TestServerUnreadableAllowlistIsUnavailable(t *testing.T) {
	s := newServerWithPolicy(t, NewFileAllowlist(filepath.Join(t.TempDir(), "missing")))

	_, err := s.Seal(context.Background(), &kms.Request{NodeUuid: nodeA, Data: passphrase()})
	if code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", code(err))
	}
}
