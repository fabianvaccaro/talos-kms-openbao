package kmsserver

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
)

// envelopeMagic versions the plaintext layout sent to OpenBao.
const envelopeMagic = "talos-kms-openbao/v1\x00"

// uuidPattern accepts the SMBIOS UUID Talos sends, in canonical form.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var (
	errBadUUID      = errors.New("invalid node uuid")
	errBadEnvelope  = errors.New("malformed envelope")
	errNodeMismatch = errors.New("ciphertext belongs to another node")
)

// normalizeUUID lower-cases and validates a node UUID.
func normalizeUUID(raw string) (string, error) {
	uuid := strings.ToLower(strings.TrimSpace(raw))
	if !uuidPattern.MatchString(uuid) {
		return "", errBadUUID
	}

	return uuid, nil
}

// wrap binds data to the node: the UUID is encrypted together with the data,
// so OpenBao's authenticated encryption makes the binding tamper-proof.
func wrap(uuid string, data []byte) []byte {
	out := make([]byte, 0, len(envelopeMagic)+len(uuid)+1+len(data))
	out = append(out, envelopeMagic...)
	out = append(out, uuid...)
	out = append(out, 0)

	return append(out, data...)
}

// unwrap returns the data only if the envelope was sealed for uuid.
func unwrap(uuid string, plaintext []byte) ([]byte, error) {
	rest, ok := bytes.CutPrefix(plaintext, []byte(envelopeMagic))
	if !ok {
		return nil, errBadEnvelope
	}

	owner, data, ok := bytes.Cut(rest, []byte{0})
	if !ok {
		return nil, errBadEnvelope
	}

	if string(owner) != uuid {
		return nil, errNodeMismatch
	}

	return data, nil
}
