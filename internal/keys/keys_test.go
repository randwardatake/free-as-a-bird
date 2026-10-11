package keys

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	sk, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(path, sk); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, sk); err == nil {
		t.Fatal("existing key overwritten")
	}
	got, err := Load(path)
	if err != nil || !Public(got).Equal(Public(sk)) {
		t.Fatalf("load: %v", err)
	}
	os.Chmod(path, 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("world-readable key accepted")
	}
}

func TestThreadKey(t *testing.T) {
	sk, _ := Generate()
	a := ThreadKey(sk, []byte("salt-a"))
	if !Public(a).Equal(Public(ThreadKey(sk, []byte("salt-a")))) {
		t.Fatal("thread key not deterministic")
	}
	if Public(a).Equal(Public(ThreadKey(sk, []byte("salt-b")))) {
		t.Fatal("different threads share a key")
	}
	if Public(a).Equal(Public(sk)) {
		t.Fatal("thread key equals the master key")
	}
}

func TestPublicKeyText(t *testing.T) {
	sk, _ := Generate()
	pk := Public(sk)
	var back PublicKey
	if err := back.UnmarshalText([]byte(pk.String())); err != nil || !back.Equal(pk) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := ParsePublicKey("short"); err == nil {
		t.Fatal("short key accepted")
	}
}
