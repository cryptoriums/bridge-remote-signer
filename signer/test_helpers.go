package signer

import (
	"bytes"
	"strings"
	"testing"
)

func requireNoError(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}

func requireEqual(t *testing.T, expected, actual []byte, msg string) {
	t.Helper()
	if !bytes.Equal(expected, actual) {
		t.Fatalf("%s:\nexpected: %x\ngot: %x", msg, expected, actual)
	}
}

func requireEqualString(t *testing.T, a, b string, msg string) {
	t.Helper()

	if !strings.EqualFold(a, b) {
		t.Fatalf("%s:\nexpected: %s\ngot: %s", msg, a, b)
	}

}

func requireLen(t *testing.T, b []byte, expected int) {
	t.Helper()
	if len(b) != expected {
		t.Fatalf("expected length %d, got %d", expected, len(b))
	}
}
