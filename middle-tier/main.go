package main

import (
	
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"context"
	"io/ioutil"
	"time"
	"net"
	
	// SPIFFE
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	
	// To generate a sample ZKP response
	"crypto/sha256"

)

type FileContents struct {
	OauthClaims					map[string]interface{} `json:",omitempty"`
	DASVIDToken					string `json:",omitempty"`
	ZKP							string `json:",omitempty"`
}

type Contents struct {
	DasvidExpValidation 		*bool `json:",omitempty"`
	DasvidExpRemainingTime		string `json:",omitempty"`
	DasvidSigValidation 		*bool `json:",omitempty"`
	DASVIDToken					string `json:",omitempty"`
}

type Balancetemp struct {
	User						string `json:",omitempty"`
	Balance						int `json`
	Returnmsg					string `json:",omitempty"`
}

var temp Contents

const (
	socketPath    = "unix:///tmp/spire-agent/public/api.sock"
	// Define local environment settings
	AssertingwlIP 	= "192.168.0.5:8443" 
	TargetwlIP		= "192.168.0.5:8444"
)

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s execution time is %s", name, elapsed)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	http.HandleFunc("/get_balance", Get_balanceHandler)
	http.HandleFunc("/deposit", DepositHandler)

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID - Client must be from this trust domain
	clientID := spiffeid.RequireTrustDomainFromString("example.org")
	
	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match the allowed SPIFFE-ID
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(clientID))
	server := &http.Server{
		Addr:      ":8445",
		TLSConfig: tlsConfig,
	}
	
	log.Printf("Start serving Middle tier API...")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Error on serve: %v", err)
	}
	
}

func Get_balanceHandler(w http.ResponseWriter, r *http.Request) {
	
	defer timeTrack(time.Now(), "Get_balanceHandler")

	var tempbalance Balancetemp

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	// Validate DASVID
	datoken := r.FormValue("DASVID")
	endpoint := "https://"+AssertingwlIP+"/validate?DASVID="+datoken

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", AssertingwlIP, err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	err = json.Unmarshal([]byte(body), &temp)
	if err != nil {
		log.Fatalf("error:", err)
	}

	var returnmsg string

	log.Println("Sig validation: ", *temp.DasvidSigValidation)
	log.Println("exp validation: ", *temp.DasvidExpValidation)

	if (*temp.DasvidSigValidation == false) {
				
		returnmsg = "DA-SVID signature validation error"

		tempbalance = Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg: 	returnmsg,
		}

		json.NewEncoder(w).Encode(tempbalance)
		return
	}

	if (*temp.DasvidExpValidation == false) {
				
		returnmsg = "DA-SVID expiration validation error"
		log.Println("Return Msg: ", tempbalance.Returnmsg)

		tempbalance = Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg: 	returnmsg,
		}

		json.NewEncoder(w).Encode(tempbalance)
		return
	}

	tempbalance = introspect(r.FormValue("DASVID"), *client)
	if tempbalance.Returnmsg != "" {
		log.Println("ZKP error! %v", tempbalance.Returnmsg)
		json.NewEncoder(w).Encode(tempbalance)
	}

	// Access Target WL and request DASVID user balance
	endpoint = "https://"+TargetwlIP+"/get_balance?DASVID="+r.FormValue("DASVID")

	response, err = client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", TargetwlIP, err)
	}

	defer response.Body.Close()
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// Receive data and return it to subject.
	err = json.Unmarshal([]byte(body), &tempbalance)
	if err != nil {
		fmt.Println("error:", err)
	}

	json.NewEncoder(w).Encode(tempbalance)

}

func DepositHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "DepositHandler")

	var tempbalance Balancetemp

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	// Validate DASVID
	endpoint := "https://"+AssertingwlIP+"/validate?DASVID="+r.FormValue("DASVID")

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", AssertingwlIP, err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	err = json.Unmarshal([]byte(body), &temp)
	if err != nil {
		log.Fatalf("error:", err)
	}

	var returnmsg string

	log.Println("Sig validation: ", *temp.DasvidSigValidation)
	log.Println("exp validation: ", *temp.DasvidExpValidation)

	if (*temp.DasvidSigValidation == false) {
				
		returnmsg = "DA-SVID signature validation error"

		tempbalance = Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg: 	returnmsg,
		}

		json.NewEncoder(w).Encode(tempbalance)
		return
	}

	if (*temp.DasvidExpValidation == false) {
				
		returnmsg = "DA-SVID expiration validation error"
		log.Println("Return Msg: ", tempbalance.Returnmsg)

		tempbalance = Balancetemp{
			User:		"",
			Balance:	0,
			Returnmsg: 	returnmsg,
		}

		json.NewEncoder(w).Encode(tempbalance)
		return
	}

	tempbalance = introspect(r.FormValue("DASVID"), *client)
	if tempbalance.Returnmsg != "" {
		log.Println("ZKP error! %v", tempbalance.Returnmsg)
		json.NewEncoder(w).Encode(tempbalance)
	}

	endpoint = "https://"+TargetwlIP+"/deposit?DASVID="+r.FormValue("DASVID")+"&deposit="+r.FormValue("deposit")

	response, err = client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", TargetwlIP, err)
	}

	defer response.Body.Close()
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	// Receive data and return it to subject.
	err = json.Unmarshal([]byte(body), &tempbalance)
	if err != nil {
		fmt.Println("error:", err)
	}

	json.NewEncoder(w).Encode(tempbalance)
	
}

func GetOutboundIP(port string) string {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
	StrIPlocal := fmt.Sprintf("%v", localAddr.IP)
	uri := StrIPlocal + port
    return uri
}

func introspect(datoken string, client http.Client) (tempbalance Balancetemp) {
	
	// Introspect DA-SVID
	var returnmsg string
	var rcvresp FileContents

	endpoint := "https://"+AssertingwlIP+"/introspect?DASVID="+datoken

	response, err := client.Get(endpoint)
	if err != nil {
		log.Fatalf("Error connecting to %q: %v", AssertingwlIP, err)
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read body: %v", err)
	}

	err = json.Unmarshal([]byte(body), &rcvresp)
	if err != nil {
		log.Fatalf("error:", err)
	}

	zkptmp := sha256.New()
	zkptmp.Write([]byte(fmt.Sprintf("%v",datoken)))

	if fmt.Sprintf("%x",zkptmp.Sum(nil)) != rcvresp.ZKP {
		returnmsg = "ZKP error!"
	} else { returnmsg = "" }

	tempbalance = Balancetemp{
		Returnmsg: 	returnmsg,
	}

	return tempbalance
}