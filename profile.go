package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/dchest/scrypt"
)

const (
	minMasterLength   = 1
	maxMasterLength   = 128
	minURLLength      = 0
	maxURLLength      = 256
	minUsernameLength = 0
	maxUsernameLength = 256
	minLength         = 1
	maxLength         = 32
	defaultLength     = 16
	minGeneration     = 0
	maxGeneration     = 1 << 50
	defaultGeneration = 0
	minChar           = 32
	maxChar           = 126

	scryptN = 16384
	scryptR = 8
	scryptP = 1
)

type Profile struct {
	UUID        string     `json:"uuid"`
	Name        string     `json:"name,omitempty"`
	Username    string     `json:"username,omitempty"`
	URL         string     `json:"url,omitempty"`
	Generation  int        `json:"generation,omitempty"`
	Length      int        `json:"length,omitempty"`
	Lower       bool       `json:"lower,omitempty"`
	Upper       bool       `json:"upper,omitempty"`
	Digits      bool       `json:"digits,omitempty"`
	Punctuation bool       `json:"punctuation,omitempty"`
	Spaces      bool       `json:"spaces,omitempty"`
	Include     string     `json:"include,omitempty"`
	Exclude     string     `json:"exclude,omitempty"`
	ModifiedAt  *time.Time `json:"modified_at,omitempty"`
}

// String gives back a printable summary of a profile.
func (p *Profile) String() string {
	charset := ""
	if p.Lower {
		charset += "a–z"
	}
	if p.Upper {
		charset += "A–Z"
	}
	if p.Digits {
		charset += "0–9"
	}
	if p.Punctuation {
		charset += "[punct]"
	}
	if p.Spaces {
		charset += "[space]"
	}
	if p.Include != "" {
		charset += "+[" + p.Include + "]"
	}
	if p.Exclude != "" {
		charset += "-[" + p.Exclude + "]"
	}
	return fmt.Sprintf("[%s] user:%s gen:%d len:%d chars:%s", p.URL, p.Username, p.Generation, p.Length, charset)
}

// Match returns true if this profile matches the given profile in a search.
func (p *Profile) Match(q *Profile) bool {
	if p.Length == 0 {
		return false
	}
	if q.Username != "" && !strings.Contains(p.Username, strings.ToLower(q.Username)) {
		return false
	}
	if q.URL != "" && !strings.Contains(p.URL, strings.ToLower(q.URL)) {
		return false
	}
	if q.Name != "" && !strings.Contains(strings.ToLower(p.Name), strings.ToLower(q.Name)) {
		return false
	}
	return true
}

// Validate normalizes some profile parameters and verifies their validity.
func (p *Profile) Validate() error {
	// username must be within length limits
	if len(p.Username) < minUsernameLength || len(p.Username) > maxUsernameLength {
		return fmt.Errorf("username must be between %d and %d characters", minUsernameLength, maxUsernameLength)
	}

	// username must not contain illegal characters
	for _, r := range p.Username {
		if r < minChar || r > maxChar {
			return fmt.Errorf("username/email contains an illegal character")
		}
	}

	// convert username to lower case
	p.Username = strings.ToLower(p.Username)

	// URL must be within length limits
	if len(p.URL) < minURLLength || len(p.URL) > maxURLLength {
		return fmt.Errorf("website URL must be between %d and %d characters", minURLLength, maxURLLength)
	}

	// URL must not contain illegal characters
	for _, r := range p.URL {
		if r < minChar || r > maxChar {
			return fmt.Errorf("website URL contains an illegal character")
		}
	}

	// convert URL to lower case
	p.URL = strings.ToLower(p.URL)

	// generation must be within limits
	if p.Generation < minGeneration || p.Generation > maxGeneration {
		return fmt.Errorf("generation must be between %d and %d", minGeneration, maxGeneration)
	}

	// length must be within limits
	if p.Length < minLength || p.Length > maxLength {
		return fmt.Errorf("length must be between %d and %d", minLength, maxLength)
	}

	// normalize includes and excludes
	// and count the characters that we can use in passwords
	include := new(bytes.Buffer)
	exclude := new(bytes.Buffer)
	count := 0
	for r := rune(minChar); r <= rune(maxChar); r++ {
		if p.CanUse(r) {
			count++
		}

		if strings.ContainsRune(p.Exclude, r) {
			exclude.WriteRune(r)
		} else if strings.ContainsRune(p.Include, r) {
			include.WriteRune(r)
		}
	}
	p.Include = include.String()
	p.Exclude = exclude.String()

	// can we use > 1 characters?
	if count < 2 {
		return fmt.Errorf("profile does not allow > 1 possible character in password")
	}

	return nil
}

// Generate makes a password using the given master password.
func (p *Profile) Generate(master string) string {
	// generate the password
	passwordPart := master + "\t" + p.URL + "\t" + p.Username
	saltPart := strconv.Itoa(p.Generation)
	hash, err := scrypt.Key([]byte(passwordPart), []byte(saltPart), scryptN, scryptR, scryptP, p.Length)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scrypt error: %v\n", err)
		os.Exit(1)
	}

	// get the character set
	chars := p.GetCharacterSet()

	// map the generated password to the character set
	pool := new(big.Int).SetBytes(hash)
	poolSize := new(big.Int).SetBit(new(big.Int), len(hash)*8, 1)

	out := new(bytes.Buffer)
	for i := 0; i < p.Length; i++ {
		// generate one number in the range len(chars)
		base := new(big.Int).Mul(pool, big.NewInt(int64(len(chars))))
		quo, rem := new(big.Int).QuoRem(base, poolSize, new(big.Int))
		pool = rem
		out.WriteByte(chars[int(quo.Int64())])
	}
	return out.String()
}

// CanUse checks if a given rune can be included in a password based on this profile.
func (p *Profile) CanUse(r rune) bool {
	use := false

	// is this a character the profile calls for?
	switch {
	case unicode.IsSpace(r):
		use = p.Spaces
	case unicode.IsLower(r):
		use = p.Lower
	case unicode.IsUpper(r):
		use = p.Upper
	case unicode.IsDigit(r):
		use = p.Digits
	default:
		use = p.Punctuation
	}

	// is this a special case?
	if strings.ContainsRune(p.Include, r) {
		use = true
	}
	if strings.ContainsRune(p.Exclude, r) {
		use = false
	}

	return use
}

// GetCharacterSet returns a string containing all the characters that can be used in the password.
func (p *Profile) GetCharacterSet() string {
	// generate the character set
	buf := new(bytes.Buffer)
	for r := rune(minChar); r <= rune(maxChar); r++ {
		if p.CanUse(r) {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Reader.Read(b); err != nil {
		panic(fmt.Sprintf("error generating random UUID: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
