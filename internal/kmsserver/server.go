// Package kmsserver implements the Talos KMS gRPC API (sidero.kms.KMSService)
// on top of a transit.Cipher. Talos sends the per-disk LUKS passphrase to Seal
// once at install time and the sealed blob to Unseal on every boot.
package kmsserver

import (
	"context"
	"errors"
	"log/slog"

	"github.com/siderolabs/kms-client/api/kms"
	"github.com/siderolabs/kms-client/pkg/constants"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/fabianvaccaro/talos-kms-openbao/internal/transit"
)

// maxSealedBytes bounds Unseal input; a transit ciphertext of a 32-byte
// passphrase plus envelope is about 150 bytes.
const maxSealedBytes = 4096

// Server serves Seal and Unseal.
type Server struct {
	kms.UnimplementedKMSServiceServer

	cipher transit.Cipher
	log    *slog.Logger
}

// New returns a Server that encrypts through cipher and logs to log.
func New(cipher transit.Cipher, log *slog.Logger) *Server {
	return &Server{cipher: cipher, log: log}
}

// Seal encrypts a node's disk passphrase, bound to the node UUID.
func (s *Server) Seal(ctx context.Context, req *kms.Request) (*kms.Response, error) {
	uuid, err := normalizeUUID(req.GetNodeUuid())
	if err != nil {
		return nil, s.reject("seal", req.GetNodeUuid(), err)
	}

	if len(req.GetData()) != constants.PassphraseSize {
		return nil, s.reject("seal", uuid, errors.New("unexpected passphrase length"))
	}

	ciphertext, err := s.cipher.Encrypt(ctx, wrap(uuid, req.GetData()))
	if err != nil {
		s.log.Error("seal failed", "node_uuid", uuid, "err", err)

		return nil, status.Error(codes.Unavailable, "key service unavailable")
	}

	s.log.Info("sealed", "node_uuid", uuid)

	return &kms.Response{Data: []byte(ciphertext)}, nil
}

// Unseal returns the passphrase if the blob was sealed for this node UUID.
func (s *Server) Unseal(ctx context.Context, req *kms.Request) (*kms.Response, error) {
	uuid, err := normalizeUUID(req.GetNodeUuid())
	if err != nil {
		return nil, s.reject("unseal", req.GetNodeUuid(), err)
	}

	if n := len(req.GetData()); n == 0 || n > maxSealedBytes {
		return nil, s.reject("unseal", uuid, errors.New("unexpected sealed length"))
	}

	plaintext, err := s.cipher.Decrypt(ctx, string(req.GetData()))
	if errors.Is(err, transit.ErrDecrypt) {
		return nil, s.deny(uuid, err)
	}

	if err != nil {
		s.log.Error("unseal failed", "node_uuid", uuid, "err", err)

		return nil, status.Error(codes.Unavailable, "key service unavailable")
	}

	data, err := unwrap(uuid, plaintext)
	if err != nil {
		return nil, s.deny(uuid, err)
	}

	s.log.Info("unsealed", "node_uuid", uuid)

	return &kms.Response{Data: data}, nil
}

func (s *Server) reject(op, uuid string, err error) error {
	s.log.Warn(op+" rejected", "node_uuid", uuid, "err", err)

	return status.Error(codes.InvalidArgument, err.Error())
}

// deny hides the reason from the caller; the log keeps it.
func (s *Server) deny(uuid string, err error) error {
	s.log.Warn("unseal denied", "node_uuid", uuid, "err", err)

	return status.Error(codes.PermissionDenied, "unseal denied")
}
