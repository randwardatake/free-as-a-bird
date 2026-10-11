package blob

import "testing"

func TestPutGetVerify(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Put([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(c); err != nil || string(got) != "hello" {
		t.Fatalf("get: %q %v", got, err)
	}
	other := Sum([]byte("other"))
	if err := s.PutVerified(other, []byte("not other")); err == nil {
		t.Fatal("bytes that do not match the CID were stored")
	}
	if s.Has(other) {
		t.Fatal("rejected blob is on disk")
	}
	if err := s.Delete(c); err != nil || s.Has(c) {
		t.Fatalf("delete: %v", err)
	}
	for _, bad := range []string{"../../etc/passwd", "", "bafy", "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"} {
		if _, err := s.Get(bad); err == nil {
			t.Errorf("Get(%q) succeeded", bad)
		}
	}
}
