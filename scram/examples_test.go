package scram_test

import (
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/mjl-/mox/scram"
)

func Example() {
	// Prepare credentials.
	//
	// The client normally remembers the password and uses it during authentication.
	//
	// The server sets the iteration count, generates a salt and uses the password once
	// to generate salted password hash. The salted password hash is used to
	// authenticate the client during authentication.
	iterations := 4096
	salt := scram.MakeRandom()
	password := "test1234"
	saltedPassword := scram.SaltPassword(sha256.New, password, salt, iterations)

	check := func(err error, msg string) {
		if err != nil {
			log.Fatalf("%s: %s", msg, err)
		}
	}

	// Make a new client for authenticating user mjl with SCRAM-SHA-256.
	username := "mjl"
	authz := ""
	client := scram.NewClient(sha256.New, username, authz, false, nil)
	clientFirst, err := client.ClientFirst()
	check(err, "client.ClientFirst")

	// Instantiate a new server with the initial message from the client.
	server, err := scram.NewServer(sha256.New, []byte(clientFirst), nil, false)
	check(err, "NewServer")

	// Generate first message from server to client, with a challenge.
	serverFirst, err := server.ServerFirst(iterations, salt)
	check(err, "server.ServerFirst")

	// Continue at client with first message from server, resulting in message from
	// client to server.
	clientFinal, err := client.ServerFirst([]byte(serverFirst), password)
	check(err, "client.ServerFirst")

	// Continue at server with message from client.
	// The server authenticates the client in this step.
	serverFinal, err := server.Finish([]byte(clientFinal), saltedPassword)
	if err != nil {
		fmt.Println("server does not accept client credentials")
	} else {
		fmt.Println("server has accepted client credentials")
	}

	// Finally, the client verifies that the server knows the salted password hash.
	err = client.ServerFinal([]byte(serverFinal))
	if err != nil {
		fmt.Println("client does not accept server")
	} else {
		fmt.Println("client has accepted server")
	}

	// Output:
	// server has accepted client credentials
	// client has accepted server
}
