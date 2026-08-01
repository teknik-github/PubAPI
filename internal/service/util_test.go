package service

import "testing"

func TestHash(t *testing.T) {
	got, err := Hash("sha256", "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("sha256(hello) = %s, want %s", got, want)
	}
	if _, err := Hash("nope", "x"); err == nil {
		t.Error("expected error for unknown algorithm")
	}
}

func TestIdentifyHash(t *testing.T) {
	cases := map[string]string{
		"5d41402abc4b2a76b9719d911017c592": "MD5 / NTLM / MD4",
		"$2b$12$abcdefghijklmnopqrstuv":    "bcrypt",
	}
	for in, want := range cases {
		got := IdentifyHash(in)
		if len(got) == 0 || got[0] != want {
			t.Errorf("IdentifyHash(%q) = %v, want first = %q", in, got, want)
		}
	}
}

func TestTransformRoundTrip(t *testing.T) {
	for _, scheme := range []string{"base64", "base64url", "base32", "hex", "url"} {
		enc, err := Transform("encode", scheme, "admin:secret")
		if err != nil {
			t.Fatalf("%s encode: %v", scheme, err)
		}
		dec, err := Transform("decode", scheme, enc)
		if err != nil {
			t.Fatalf("%s decode: %v", scheme, err)
		}
		if dec != "admin:secret" {
			t.Errorf("%s round-trip = %q, want admin:secret", scheme, dec)
		}
	}
}

func TestDecodeJWT(t *testing.T) {
	tok := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.sig"
	res, err := DecodeJWT(tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Algorithm != "HS256" {
		t.Errorf("alg = %q, want HS256", res.Algorithm)
	}
	if res.Payload["name"] != "John Doe" {
		t.Errorf("payload name = %v, want John Doe", res.Payload["name"])
	}
	if _, err := DecodeJWT("not.a.jwt.token"); err == nil {
		t.Error("expected error for malformed token")
	}
}

func TestValidateDomain(t *testing.T) {
	if _, err := ValidateDomain("example.com"); err != nil {
		t.Errorf("valid domain rejected: %v", err)
	}
	for _, bad := range []string{"", "not a domain", "http://x.com", "-bad.com"} {
		if _, err := ValidateDomain(bad); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}
