package land

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestWordlistIsCanonical(t *testing.T) {
	// SHA-256 of bip-0039/english.txt in github.com/bitcoin/bips.
	const want = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(englishTxt))); got != want {
		t.Fatalf("wordlist sha256 = %s, want %s", got, want)
	}
}

// Test vectors from the reference BIP-39 implementation (trezor/python-mnemonic).
var phraseVectors = []struct{ entropy, phrase string }{
	{"00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"},
	{"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"},
	{"80808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"},
	{"ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"},
	{"0000000000000000000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"},
	{"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"},
	{"8080808080808080808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"},
	{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"},
}

func TestPhraseVectors(t *testing.T) {
	for _, v := range phraseVectors {
		secret, _ := hex.DecodeString(v.entropy)
		m := &Master{secret: secret}
		if got := m.Phrase(); got != v.phrase {
			t.Errorf("Phrase(%s)\n got %s\nwant %s", v.entropy, got, v.phrase)
		}
		back, err := ParsePhrase(v.phrase)
		if err != nil {
			t.Errorf("ParsePhrase(%q): %v", v.phrase, err)
			continue
		}
		if !bytes.Equal(back.secret, secret) {
			t.Errorf("ParsePhrase(%q) = %x, want %s", v.phrase, back.secret, v.entropy)
		}
	}
}

func TestNewMasterRoundTrip(t *testing.T) {
	for _, words := range []int{Words12, Words24} {
		m, err := NewMaster(words)
		if err != nil {
			t.Fatal(err)
		}
		p := m.Phrase()
		if n := len(strings.Fields(p)); n != words {
			t.Fatalf("NewMaster(%d) phrase has %d words", words, n)
		}
		// Sloppy typing from a paper backup is fine: case and spacing.
		back, err := ParsePhrase("  " + strings.ToUpper(strings.ReplaceAll(p, " ", " \n\t")) + " ")
		if err != nil {
			t.Fatal(err)
		}
		if !back.LandKey().Equal(m.LandKey()) {
			t.Fatal("land key differs after phrase round trip")
		}
		if !back.RouteKey().Equal(m.RouteKey()) {
			t.Fatal("route key differs after phrase round trip")
		}
	}
	if _, err := NewMaster(18); err == nil {
		t.Fatal("18 words accepted")
	}
}

func TestParsePhraseRejects(t *testing.T) {
	good := phraseVectors[0].phrase
	words := strings.Fields(phraseVectors[4].phrase)
	cases := map[string]string{
		"empty":        "",
		"wrong length": strings.Join(words[:15], " "),
		"unknown word": strings.Replace(good, "about", "abuot", 1),
		"checksum":     strings.Replace(good, "about", "abandon", 1),
		"swapped":      "about " + strings.TrimSuffix(good, " about"),
	}
	for name, p := range cases {
		if _, err := ParsePhrase(p); err == nil {
			t.Errorf("%s: %q accepted", name, p)
		}
	}
}

// The derivations must never change: a land's keys are recreated from its
// phrase alone, so a changed derivation silently loses every land. The
// expected values were computed independently with Python's hmac module.
func TestDerivationKnownAnswer(t *testing.T) {
	m := &Master{secret: make([]byte, 32)}
	const (
		wantLandSeed  = "fd685e05f9f5ec2f863010974d2c0a8a228f528604a8c00697316d1142fb5715"
		wantRouteSeed = "53507b1f0553de6d926f55842cd732b4e764054e8b0175a0c828a21ef11772c2"
	)
	if got := hex.EncodeToString(m.LandKey().Seed()); got != wantLandSeed {
		t.Errorf("land seed = %s, want %s", got, wantLandSeed)
	}
	if got := hex.EncodeToString(m.derive(routeInfo)); got != wantRouteSeed {
		t.Errorf("route seed = %s, want %s", got, wantRouteSeed)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	a, _ := NewMaster(Words24)
	b, _ := NewMaster(Words24)
	if a.LandKey().Equal(b.LandKey()) || a.RouteKey().Equal(b.RouteKey()) {
		t.Fatal("two masters derived the same key")
	}
	if bytes.Equal(a.derive(landInfo), a.derive(routeInfo)) {
		t.Fatal("land and route keys share a seed")
	}
}

func TestMasterRedacted(t *testing.T) {
	m, _ := NewMaster(Words12)
	for _, s := range []string{fmt.Sprint(m), fmt.Sprintf("%v %s", m, m)} {
		if strings.Contains(s, fmt.Sprint(m.secret)) || strings.Contains(s, hex.EncodeToString(m.secret)) {
			t.Fatalf("secret leaked in %q", s)
		}
	}
}
