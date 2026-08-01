package service

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net/url"
	"regexp"
	"strings"
)

// Hash computes the digest of text using the named algorithm.
func Hash(algo, text string) (string, error) {
	data := []byte(text)
	switch strings.ToLower(algo) {
	case "md5":
		sum := md5.Sum(data)
		return hex.EncodeToString(sum[:]), nil
	case "sha1":
		sum := sha1.Sum(data)
		return hex.EncodeToString(sum[:]), nil
	case "sha256":
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:]), nil
	case "sha512":
		sum := sha512.Sum512(data)
		return hex.EncodeToString(sum[:]), nil
	case "crc32":
		return fmt.Sprintf("%08x", crc32.ChecksumIEEE(data)), nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %q (use md5, sha1, sha256, sha512, crc32)", algo)
	}
}

// HashAllResult contains every supported digest for a single input.
type HashAllResult struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
	CRC32  string `json:"crc32"`
}

// HashAll computes all supported digests at once.
func HashAll(text string) HashAllResult {
	md5s, _ := Hash("md5", text)
	sha1s, _ := Hash("sha1", text)
	sha256s, _ := Hash("sha256", text)
	sha512s, _ := Hash("sha512", text)
	crc, _ := Hash("crc32", text)
	return HashAllResult{MD5: md5s, SHA1: sha1s, SHA256: sha256s, SHA512: sha512s, CRC32: crc}
}

// hashType pairs a candidate hash algorithm with the hex length that implies it.
type hashType struct {
	name   string
	length int
}

var hashTypesByLen = []hashType{
	{"MD5 / NTLM / MD4", 32},
	{"SHA-1", 40},
	{"SHA-224", 56},
	{"SHA-256", 64},
	{"SHA-384", 96},
	{"SHA-512", 128},
	{"CRC32", 8},
}

var hexRe = regexp.MustCompile(`^[a-fA-F0-9]+$`)

// IdentifyHash guesses possible hash algorithms from a digest's shape.
func IdentifyHash(hash string) []string {
	hash = strings.TrimSpace(hash)
	var out []string

	// Prefixed formats are unambiguous.
	switch {
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		return []string{"bcrypt"}
	case strings.HasPrefix(hash, "$argon2"):
		return []string{"Argon2"}
	case strings.HasPrefix(hash, "$6$"):
		return []string{"sha512crypt (Unix)"}
	case strings.HasPrefix(hash, "$5$"):
		return []string{"sha256crypt (Unix)"}
	case strings.HasPrefix(hash, "$1$"):
		return []string{"md5crypt (Unix)"}
	}

	if !hexRe.MatchString(hash) {
		return []string{"unknown (non-hex / unrecognized format)"}
	}
	for _, ht := range hashTypesByLen {
		if len(hash) == ht.length {
			out = append(out, ht.name)
		}
	}
	if len(out) == 0 {
		out = append(out, fmt.Sprintf("unknown (hex length %d)", len(hash)))
	}
	return out
}

// Transform encodes or decodes text using the named scheme.
// action is "encode" or "decode"; scheme is base64, base64url, base32, hex, url.
func Transform(action, scheme, text string) (string, error) {
	enc := action == "encode"
	dec := action == "decode"
	if !enc && !dec {
		return "", fmt.Errorf("action must be 'encode' or 'decode'")
	}
	switch strings.ToLower(scheme) {
	case "base64":
		if enc {
			return base64.StdEncoding.EncodeToString([]byte(text)), nil
		}
		b, err := base64.StdEncoding.DecodeString(text)
		return string(b), wrapDecode(err)
	case "base64url":
		if enc {
			return base64.URLEncoding.EncodeToString([]byte(text)), nil
		}
		b, err := base64.URLEncoding.DecodeString(text)
		return string(b), wrapDecode(err)
	case "base32":
		if enc {
			return base32.StdEncoding.EncodeToString([]byte(text)), nil
		}
		b, err := base32.StdEncoding.DecodeString(text)
		return string(b), wrapDecode(err)
	case "hex":
		if enc {
			return hex.EncodeToString([]byte(text)), nil
		}
		b, err := hex.DecodeString(text)
		return string(b), wrapDecode(err)
	case "url":
		if enc {
			return url.QueryEscape(text), nil
		}
		s, err := url.QueryUnescape(text)
		return s, wrapDecode(err)
	default:
		return "", fmt.Errorf("unsupported scheme: %q (use base64, base64url, base32, hex, url)", scheme)
	}
}

func wrapDecode(err error) error {
	if err != nil {
		return fmt.Errorf("decode failed: %w", err)
	}
	return nil
}

// JWTResult is a decoded (but NOT signature-verified) JWT.
type JWTResult struct {
	Header    map[string]interface{} `json:"header"`
	Payload   map[string]interface{} `json:"payload"`
	Signature string                 `json:"signature"`
	Algorithm string                 `json:"algorithm,omitempty"`
	Note      string                 `json:"note"`
}

// DecodeJWT splits and base64url-decodes a JWT's header and payload.
// It does not verify the signature — this is an inspection helper only.
func DecodeJWT(token string) (*JWTResult, error) {
	token = strings.TrimSpace(token)
	token = strings.TrimPrefix(token, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a valid JWT: expected 3 dot-separated segments, got %d", len(parts))
	}
	header, err := decodeJWTSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	payload, err := decodeJWTSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	res := &JWTResult{
		Header:    header,
		Payload:   payload,
		Signature: parts[2],
		Note:      "Signature is NOT verified. Decoded for inspection only.",
	}
	if alg, ok := header["alg"].(string); ok {
		res.Algorithm = alg
	}
	return res, nil
}

func decodeJWTSegment(seg string) (map[string]interface{}, error) {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		// Some tokens include padding; fall back to standard URL encoding.
		b, err = base64.URLEncoding.DecodeString(seg)
		if err != nil {
			return nil, err
		}
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
