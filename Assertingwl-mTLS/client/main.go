package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"net"
	"fmt"
	"os"


	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	// Workload API socket path
	socketPath    = "unix:///tmp/spire-agent/public/api.sock"
)

func GetOutboundIP() net.IP {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)

    return localAddr.IP
}

func main() {

// Usage: ./client <operation> <parameter>
// 
// Supported Operations: mint, keys, validate
// Parameters: mint requires Oauth Token. Validate requires DASVID to be validated.

// example:
// ./client mint <OAUTH TOKEN>

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var endpoint string
	
	// Retrieve local IP
	// In this PoC example, client and server are running in the same host, so serverIP = clientIP 
	Iplocal := GetOutboundIP()
	StrIPlocal := fmt.Sprintf("%v", Iplocal)
	serverURL := StrIPlocal + ":8443"

	operation := os.Args[1]

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID
	serverID := spiffeid.RequireTrustDomainFromString("example.org")

	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	switch operation {
    case "mint":
		// mint endpoint test
		token := os.Args[2]
		endpoint = "https://"+serverURL+"/mint?AccessToken="+token

    case "keys":
        // keys endpoint test
		endpoint = "https://"+serverURL+"/keys"

    case "validate":
		
		dasvid := os.Args[2]
		// validate endpoint test
		endpoint = "https://"+serverURL+"/validate?DASVID="+dasvid

	case "introspect":
		
		dasvid := os.Args[2]
		// introspect endpoint test
		endpoint = "https://"+serverURL+"/introspect?DASVID="+dasvid
		
	}

	// fmt.Println(endpoint)
	r, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", serverURL, err)
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	fmt.Printf("%s", body)
}
