package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"
	"unicode"

	"github.com/dchest/scrypt"
	"github.com/russross/envflag"
)

const (
	minMasterLength   int = 1
	maxMasterLength       = 128
	minURLLength          = 0
	maxURLLength          = 256
	minUsernameLength     = 0
	maxUsernameLength     = 256
	minLength             = 1
	maxLength             = 32
	defaultLength         = 16
	minGeneration         = 0
	maxGeneration         = 1 << 50
	minChar               = 32
	maxChar               = 126

	scryptN int = 16384
	scryptR     = 8
	scryptP     = 1
)

func main() {
	var (
		master              string
		username, url       string
		generation          int
		length              int
		lower, upper        bool
		digits, punctuation bool
		spaces              bool
		include, exclude    string
	)

	// gather options
	envflag.StringVar(&master, "master", "", "Master password")
	envflag.StringVar(&username, "username", "", "User name/email")
	envflag.StringVar(&url, "url", "", "Website URL")
	envflag.IntVar(&generation, "generation", 0, "Generation counter")
	envflag.IntVar(&length, "length", defaultLength, "Password length")
	envflag.BoolVar(&lower, "lower", true, "Include lower-case letters")
	envflag.BoolVar(&upper, "upper", true, "Include upper-case letters")
	envflag.BoolVar(&digits, "digits", true, "Include digits")
	envflag.BoolVar(&punctuation, "punctuation", true, "Include punctuation")
	envflag.BoolVar(&spaces, "spaces", false, "Include spaces")
	envflag.StringVar(&include, "include", "", "Include specific ASCII characters")
	envflag.StringVar(&exclude, "exclude", "", "Exclude specific ASCII characters")
	flag.Parse()

	// validate inputs
	if len(master) < minMasterLength || len(master) > maxMasterLength {
		log.Fatalf("master password must be between %d and %d characters", minMasterLength, maxMasterLength)
	}
	if len(url) < minURLLength || len(url) > maxURLLength {
		log.Fatalf("website URL must be between %d and %d characters", minURLLength, maxURLLength)
	}
	if len(username) < minUsernameLength || len(username) > maxUsernameLength {
		log.Fatalf("username must be between %d and %d characters", minUsernameLength, maxUsernameLength)
	}
	if length < minLength || length > maxLength {
		log.Fatalf("length must be between %d and %d", minLength, maxLength)
	}
	if generation < minGeneration || generation > maxGeneration {
		log.Fatalf("generation must be between %d and %d", minGeneration, maxGeneration)
	}
	for _, r := range master {
		if r < minChar || r > maxChar {
			log.Fatalf("master password contains an illegal character")
		}
	}
	for _, r := range username {
		if r < minChar || r > maxChar {
			log.Fatalf("username/email contains an illegal character")
		}
	}
	for _, r := range url {
		if r < minChar || r > maxChar {
			log.Fatalf("website URL contains an illegal character")
		}
	}

	// generate the password
	passwordPart := master + "\t" + url + "\t" + username
	saltPart := strconv.Itoa(generation)
	hash, err := scrypt.Key([]byte(passwordPart), []byte(saltPart), scryptN, scryptR, scryptP, length)
	if err != nil {
		log.Fatalf("scrypt error: %v", err)
	}

	// generate the character set
	buf := new(bytes.Buffer)
	for r := rune(minChar); r <= rune(maxChar); r++ {
		use := false

		// is this a character the profile calls for?
		switch {
		case unicode.IsSpace(r):
			use = spaces
		case unicode.IsLower(r):
			use = lower
		case unicode.IsUpper(r):
			use = upper
		case unicode.IsDigit(r):
			use = digits
		default:
			use = punctuation
		}

		// is this a special case?
		if strings.ContainsRune(include, r) {
			use = true
		}
		if strings.ContainsRune(exclude, r) {
			use = false
		}

		if use {
			buf.WriteRune(r)
		}
	}
	chars := buf.String()

	// map the generated password to the character set
	pool := new(big.Int).SetBytes(hash)
	poolSize := new(big.Int).SetBit(new(big.Int), len(hash)*8, 1)

	out := new(bytes.Buffer)
	for i := 0; i < length; i++ {
		// generate one number in the range len(chars)
		base := new(big.Int).Mul(pool, big.NewInt(int64(len(chars))))
		quo, rem := new(big.Int).QuoRem(base, poolSize, new(big.Int))
		pool = rem
		out.WriteByte(chars[int(quo.Int64())])
	}
	password := out.String()

	// report the generated password
	fmt.Printf("%s\n", password)
}
