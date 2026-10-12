package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

// These vectors also test the dashboard and CLI implementations. The salt is
// bytes 0..31; real owner commitments use a fresh cryptographically random salt.
var ownerVectors = []struct {
	secret string
	phc    string
}{
	{"correct horse battery staple", "$argon2id$v=19$m=262144,t=3,p=4$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$h4BcgYbxSwglIl1rEHzTAlwiKVj4pBXM5TDwAfSAFEg"},
	{"  Café workspace 🔐\n", "$argon2id$v=19$m=262144,t=3,p=4$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$a0FZaNclCYyaPhjUatURHT9w5vA+/5MPWZZCRzopI1k"},
}

func TestWorkspaceKeyPreservesRawBytes(t *testing.T) {
	for _, raw := range [][]byte{[]byte(ownerVectors[1].secret), bytes.Repeat([]byte{0xff}, minVolumeKeyBytes), bytes.Repeat([]byte{0}, volumeKeyBytes), bytes.Repeat([]byte{'a'}, maxVolumeKeyBytes)} {
		got, err := workspaceKey(base64.StdEncoding.EncodeToString(raw))
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("workspace key of %d bytes changed: %v", len(raw), err)
		}
	}
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte{'a'}, minVolumeKeyBytes-1), bytes.Repeat([]byte{'a'}, maxVolumeKeyBytes+1)} {
		if _, err := workspaceKey(base64.StdEncoding.EncodeToString(raw)); err == nil {
			t.Fatalf("accepted %d-byte workspace key", len(raw))
		}
	}
	if _, err := workspaceKey("not base64!"); err == nil {
		t.Fatal("accepted malformed transport encoding")
	}
}

func TestOwnerCommitmentRejectsMalformedAndAmbiguousBindings(t *testing.T) {
	legacy := strings.Repeat("ab", sha256.Size)
	valid := ownerVectors[0].phc
	for _, binding := range [][2]string{
		{"", ""}, {legacy, valid}, {"aa", ""}, {"not hex", ""},
		{"", strings.Replace(valid, "v=19", "v=16", 1)},
		{"", strings.Replace(valid, "m=262144", "m=65536", 1)},
		{"", strings.Replace(valid, "t=3", "t=1", 1)},
		{"", strings.Replace(valid, "p=4", "p=1", 1)},
		{"", strings.Replace(valid, "argon2id", "argon2i", 1)},
		{"", valid + "="}, {"", valid + "$extra"}, {"", " " + valid},
		{"", ownerArgonPHCPrefix + "AA$AA"},
		{"", strings.Replace(valid, "$h4B", "$\nh4B", 1)},
	} {
		if _, err := parseOwnerCommitment(binding[0], binding[1]); err == nil {
			t.Fatalf("accepted malformed owner binding %#v", binding)
		}
	}
}

func TestOwnerCommitmentVectorsAndLegacyCompatibility(t *testing.T) {
	for _, vector := range ownerVectors {
		owner, err := parseOwnerCommitment("", vector.phc)
		if err != nil || !owner.matches([]byte(vector.secret)) {
			t.Fatalf("Argon2id vector rejected: %v", err)
		}
		if owner.matches([]byte(vector.secret + "!")) {
			t.Fatal("accepted a different owner secret")
		}
	}
	for _, key := range [][]byte{bytes.Repeat([]byte{0xff}, volumeKeyBytes), []byte(ownerVectors[0].secret)} {
		hash := sha256.Sum256(key)
		owner, err := parseOwnerCommitment(hex.EncodeToString(hash[:]), "")
		if err != nil {
			t.Fatal(err)
		}
		if got, want := owner.matches(key), len(key) == volumeKeyBytes; got != want {
			t.Fatalf("legacy %d-byte key accepted=%t, want %t", len(key), got, want)
		}
	}
}

func TestLegacyCredentialCanUseNewOwnerBindingWithoutChangingDiskKey(t *testing.T) {
	key := make([]byte, volumeKeyBytes)
	for i := range key {
		key[i] = byte(i)
	}
	owner, err := parseOwnerCommitment("", "$argon2id$v=19$m=262144,t=3,p=4$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$INvuA1i7NO31TbJ0+2IBLInzi+mNALCQRTqQr2NN4kA")
	if err != nil || !owner.matches(key) {
		t.Fatalf("legacy key rejected by new owner commitment: %v", err)
	}
	hash := sha256.Sum256(key)
	legacy, err := parseOwnerCommitment(hex.EncodeToString(hash[:]), "")
	if err != nil || !legacy.matches(key) {
		t.Fatalf("same key rejected by legacy owner commitment: %v", err)
	}
}

func TestPassphraseEnrollmentPreservesDiskKeyAndOwner(t *testing.T) {
	box, _, call := testSandbox(t)
	vector := ownerVectors[1]
	var err error
	box.owner, err = parseOwnerCommitment("", vector.phc)
	if err != nil {
		t.Fatal(err)
	}
	testVolume(t, []byte(vector.secret))
	body := map[string]any{
		"key":    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		"volume": base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(vector.secret))),
	}
	if code := call("/enroll", body); code != http.StatusForbidden {
		t.Fatalf("trimmed passphrase accepted: %d", code)
	}
	if box.opened != nil || box.enrolled {
		t.Fatal("incorrect passphrase changed disk state")
	}
	body["volume"] = base64.StdEncoding.EncodeToString([]byte(vector.secret))
	if code := call("/enroll", body); code != http.StatusNoContent {
		t.Fatalf("exact passphrase enrollment: %d", code)
	}
	box.enrolled, box.opened = box.sealed(), nil
	if code := call("/enroll", body); code != http.StatusNoContent {
		t.Fatalf("passphrase enrollment retry after service restart: %d", code)
	}
}
