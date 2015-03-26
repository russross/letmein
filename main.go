package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/howeyc/gopass"
)

var filename = filepath.Join(os.Getenv("HOME"), ".letmeinrc")
var never = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

const defaultServer = "https://letmein-app.appspot.com"

type Client struct {
	Name     string     `json:"name"`
	Verify   string     `json:"verify"`
	Profiles []*Profile `json:"profiles,omitempty"`

	ModifiedAt     *time.Time `json:"modified_at,omitempty"`
	SyncedAt       *time.Time `json:"synced_at,omitempty"`
	PreviousSyncAt *time.Time `json:"previous_sync_at,omitempty"`

	Master string `json:"-"`
}

func (c *Client) Matches(q *Profile) []*Profile {
	out := []*Profile{}
	for _, elt := range c.Profiles {
		if elt.Match(q) {
			out = append(out, elt)
		}
	}
	return out
}

// VerifyProfile is a simple profile that generates a verification code for the master password.
// This can be used to catch typos when entering the master password.
var VerifyProfile = &Profile{
	Username:    "verify",
	URL:         "",
	Generation:  0,
	Length:      4,
	Lower:       true,
	Upper:       false,
	Digits:      false,
	Punctuation: false,
	Spaces:      false,
	Include:     "",
	Exclude:     "",
}

func main() {
	// check which subcommand is requested
	cmd := ""
	if len(os.Args) >= 2 {
		cmd = os.Args[1]
	}
	var client *Client
	modified := false

	switch cmd {
	case "create":
		os.Args = os.Args[1:]
		client = createProfile()
		modified = true
	case "delete":
		os.Args = os.Args[1:]
		client = deleteProfile()
		modified = true
	case "list":
		os.Args = os.Args[1:]
		client = listProfiles()
	case "sync":
		os.Args = os.Args[1:]
		client = syncProfiles()
		modified = true
	case "update":
		os.Args = os.Args[1:]
		client = updateProfile()
		modified = true
	case "init":
		os.Args = os.Args[1:]
		client = initProfile()
		modified = true
	default:
		fmt.Fprint(os.Stderr, `letmein is a password generator

Usage:

        letmein command [arguments]

The commands are:

    init        create a new client instance
    list        list all matching profiles with passwords
    create      create a new profile
    update      update an existing profile
    delete      delete a profile
    sync        sync profiles with server

Use "letmein command -help" for more information about a command.
`)
	}

	if client != nil && modified {
		raw, err := json.MarshalIndent(client, "", "    ")
		if err != nil {
			failf("Error encoding %s: %v\n", filename, err)
		}
		raw = append(raw, '\n')
		if err = ioutil.WriteFile(filename, raw, 0600); err != nil {
			failf("Error writing %s: %v\n", filename, err)
		}
	}
}

func createProfile() *Client {
	now := time.Now().Round(time.Millisecond)

	// gather options
	var master string
	registerMasterFlag(&master)
	p := new(Profile)
	registerProfileFlags(p)
	flag.Parse()
	master = getAndVerifyMaster(master)
	client := getClient(now, master)

	// see if this profile already exists
	matches := client.Matches(p)
	if len(matches) != 0 {
		fmt.Printf("Profile matches:\n")
		for _, elt := range matches {
			fmt.Printf("    %s\n", elt)
		}
		failf("Cannot create new profile that matches existing profile\n")
	}

	// validate the new profile
	if err := p.Validate(); err != nil {
		failf("invalid profile: %v\n", err)
	}

	p.UUID = newUUID()
	p.ModifiedAt = &now

	fmt.Printf("profile created: %s --> %s\n", p, p.Generate(master))
	client.ModifiedAt = &now
	client.Profiles = append(client.Profiles, p)

	return client
}

func updateProfile() *Client {
	now := time.Now().Round(time.Millisecond)

	// gather options
	var master string
	registerMasterFlag(&master)
	p := new(Profile)
	registerProfileFlags(p)
	flag.Parse()
	master = getAndVerifyMaster(master)
	client := getClient(now, master)

	// find this profile
	matches := client.Matches(p)
	if len(matches) > 1 {
		fmt.Printf("Profile matches:\n")
		for _, elt := range matches {
			fmt.Printf("    %s\n", elt)
		}
		failf("Cannot update profile without a unique match\n")
	}
	if len(matches) == 0 {
		failf("No matching profile found\n")
	}

	// validate the new profile
	if err := p.Validate(); err != nil {
		failf("invalid profile: %v\n", err)
	}

	q := matches[0]
	if p.Username != "" {
		q.Username = p.Username
	}
	if p.URL != "" {
		q.URL = p.URL
	}
	if p.Generation != defaultGeneration {
		q.Generation = p.Generation
	}
	if p.Length != defaultLength {
		q.Length = p.Length
	}
	q.Lower = p.Lower
	q.Upper = p.Upper
	q.Digits = p.Digits
	q.Punctuation = p.Punctuation
	q.Spaces = p.Spaces
	q.Include = p.Include
	q.Exclude = p.Exclude
	q.ModifiedAt = &now

	fmt.Printf("profile updated: %s --> %s\n", q, q.Generate(master))
	client.ModifiedAt = &now

	return client
}

func deleteProfile() *Client {
	now := time.Now().Round(time.Millisecond)

	// gather options
	var master string
	registerMasterFlag(&master)
	p := new(Profile)
	registerProfileFlags(p)
	flag.Parse()
	master = getAndVerifyMaster(master)
	client := getClient(now, master)

	// find this profile
	matches := client.Matches(p)

	if len(matches) > 1 {
		fmt.Printf("Profile matches:\n")
		for _, elt := range matches {
			fmt.Printf("    %s\n", elt)
		}
		failf("Cannot delete profile without a unique match\n")
	}
	if len(matches) == 0 {
		failf("No matching profile found\n")
	}
	q := matches[0]
	fmt.Printf("profile deleted: %s\n", q)

	q.Username = ""
	q.URL = ""
	q.Generation = 0
	q.Length = 0
	q.Lower = false
	q.Upper = false
	q.Digits = false
	q.Punctuation = false
	q.Spaces = false
	q.Include = ""
	q.Exclude = ""
	q.ModifiedAt = &now

	client.ModifiedAt = &now

	return client
}

func listProfiles() *Client {
	now := time.Now().Round(time.Millisecond)

	// gather options
	var master string
	registerMasterFlag(&master)
	p := new(Profile)
	registerProfileFlags(p)
	flag.Parse()
	master = getAndVerifyMaster(master)
	client := getClient(now, master)

	// find matching profiles
	matches := client.Matches(p)

	for _, elt := range matches {
		fmt.Printf("    %s --> %s\n", elt, elt.Generate(master))
	}

	return client
}

func registerMasterFlag(master *string) {
	flag.StringVar(master, "master", "", "Master password (or set LETMEIN_MASTER)")
}

func getAndVerifyMaster(master string) string {
	// prompt for a master password if necessary
	if len(master) == 0 {
		// get master password from environment, or from keyboard
		if s := os.Getenv("LETMEIN_MASTER"); s != "" {
			master = s
		} else {
			fmt.Printf("Master password: ")
			master = string(gopass.GetPasswdMasked())
			if len(master) == 0 {
				fmt.Fprintf(os.Stderr, "master password is required")
				os.Exit(1)
			}
		}
	}

	// validate the master password
	if len(master) < minMasterLength || len(master) > maxMasterLength {
		fmt.Fprintf(os.Stderr, "master password must be between %d and %d characters\n", minMasterLength, maxMasterLength)
		os.Exit(1)
	}
	for _, r := range master {
		if r < minChar || r > maxChar {
			fmt.Fprintf(os.Stderr, "master password contains an illegal character\n")
			os.Exit(1)
		}
	}

	return master
}

func registerProfileFlags(p *Profile) {
	flag.StringVar(&p.Username, "username", "", "User name/email")
	flag.StringVar(&p.URL, "url", "", "Website URL")
	flag.IntVar(&p.Generation, "generation", defaultGeneration, "Generation counter")
	flag.IntVar(&p.Length, "length", defaultLength, "Password length")
	flag.BoolVar(&p.Lower, "lower", true, "Include lower-case letters")
	flag.BoolVar(&p.Upper, "upper", true, "Include upper-case letters")
	flag.BoolVar(&p.Digits, "digits", true, "Include digits")
	flag.BoolVar(&p.Punctuation, "punctuation", true, "Include punctuation")
	flag.BoolVar(&p.Spaces, "spaces", false, "Include spaces")
	flag.StringVar(&p.Include, "include", "", "Include specific ASCII characters")
	flag.StringVar(&p.Exclude, "exclude", "", "Exclude specific ASCII characters")
}

func getClient(now time.Time, master string) *Client {
	// load the file
	raw, err := ioutil.ReadFile(filename)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", filename, err)
		os.Exit(1)
	} else if err != nil {
		// no profile list exists
		fmt.Fprintf(os.Stderr, "No profile data found: you must run the init function first\n")
		os.Exit(1)
	}

	client := new(Client)
	if err := json.Unmarshal(raw, &client); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", filename, err)
		os.Exit(1)
	}
	verify := VerifyProfile.Generate(master)
	if client.Verify == "" {
		client.Verify = verify
		client.ModifiedAt = &now
	} else if client.Verify != verify {
		fmt.Fprintf(os.Stderr, "Master password verification mismatch: found %s but expected %s\n", verify, client.Verify)
		os.Exit(1)
	}

	return client
}

func newClient(now time.Time, master string, name string) *Client {
	// make sure the file does not exist
	_, err := os.Stat(filename)
	if err == nil {
		fmt.Fprintf(os.Stderr, "Profile data already exists; delete %s to reset and start over\n", filename)
		os.Exit(1)
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error checking for existing profile data: %v\n", err)
		os.Exit(1)
	}
	client := &Client{
		Name:     name,
		Verify:   VerifyProfile.Generate(master),
		Profiles: []*Profile{},

		Master: master,
	}

	return client
}

func syncProfiles() *Client {
	now := time.Now().Round(time.Millisecond)

	// gather options
	var master string
	registerMasterFlag(&master)
	server := defaultServer
	verbose := false
	flag.StringVar(&server, "server", server, "Server URL")
	flag.BoolVar(&verbose, "v", verbose, "Dump messages")
	flag.Parse()
	master = getAndVerifyMaster(master)
	client := getClient(now, master)

	// prepare the sync request
	req := &Client{
		Name:           client.Name,
		Verify:         client.Verify,
		ModifiedAt:     client.ModifiedAt,
		SyncedAt:       &now,
		PreviousSyncAt: client.PreviousSyncAt,
	}
	for _, elt := range client.Profiles {
		if elt.ModifiedAt != nil {
			req.Profiles = append(req.Profiles, elt)
		}
	}
	if verbose {
		fmt.Printf("\nRequest:\n")
		dump(req)
	}
	raw, err := json.MarshalIndent(req, "", "    ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error JSON-encoding request: %v\n", err)
		os.Exit(1)
	}
	r, err := http.NewRequest("POST", server+"/api/v1noauth/sync", bytes.NewReader(raw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error forming POST request: %v\n", err)
		os.Exit(1)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending POST request to server: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Server returned an error status: %s\n", resp.Status)
		io.Copy(os.Stderr, resp.Body)
		fmt.Fprintf(os.Stderr, "\n")
		os.Exit(1)
	}

	// decode the response
	updates := new(Client)
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(updates); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding server response JSON: %v\n", err)
		os.Exit(1)
	}
	if verbose {
		fmt.Printf("\nResponse:\n")
		dump(updates)
	}

	// merge the results
	client.ModifiedAt = nil
	client.SyncedAt = nil
	client.PreviousSyncAt = updates.PreviousSyncAt

	byuuid := make(map[string]*Profile)
	for _, elt := range client.Profiles {
		// discard deleted records now that they hav been uploaded
		if elt.Length > 0 {
			byuuid[elt.UUID] = elt
		}

		// reset updated fields
		elt.ModifiedAt = nil
	}
	for _, elt := range updates.Profiles {
		// is it a delete notice?
		if elt.Length <= 0 {
			log.Printf("deleting profile: %s", byuuid[elt.UUID])
			delete(byuuid, elt.UUID)
		} else {
			if _, exists := byuuid[elt.UUID]; exists {
				log.Printf("updating profile: %s", elt)
			} else {
				log.Printf("adding profile: %s", elt)
			}

			elt.ModifiedAt = nil
			byuuid[elt.UUID] = elt
		}
	}
	client.Profiles = []*Profile{}
	for _, elt := range byuuid {
		client.Profiles = append(client.Profiles, elt)
	}
	return client
}

func initProfile() *Client {
	now := time.Now().Round(time.Millisecond)

	// gather options
	var master string
	registerMasterFlag(&master)
	server := "http://letmein-app.appspot.com"
	name := ""
	flag.StringVar(&server, "server", server, "Server URL")
	flag.StringVar(&name, "name", name, "Name to identify your account (required)")
	flag.Parse()
	if name == "" {
		fmt.Fprintf(os.Stderr, "name is required\n")
		os.Exit(1)
	}
	master = getAndVerifyMaster(master)
	client := newClient(now, master, name)
	return client
}

func failf(f string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, f, args...)
	os.Exit(1)
}

func dump(elt interface{}) {
	raw, err := json.MarshalIndent(elt, "", "    ")
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%s\n", raw)
}
