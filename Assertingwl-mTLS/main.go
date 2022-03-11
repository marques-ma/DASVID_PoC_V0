package main
/*
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "./poclib/rsa_sig_proof.h"
#include "./poclib/rsa_bn_sig.h"
#include "./poclib/rsa_sig_proof_util.h"

#cgo CFLAGS: -g -Wall -m64 -I${SRCDIR}
#cgo pkg-config: --static libssl libcrypto
#cgo LDFLAGS: -L${SRCDIR}

*/
import "C"

import (
	
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"context"
	"io"
	"time"
	"bufio"

	// SPIFFE
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	
	// dasvid lib
	dasvid "github.com/marco-developer/dasvid/poclib"

	// To generate a sample ZKP response
	// "crypto/sha256"

)

type FileContents struct {
	OauthToken					string `json:OauthToken",omitempty"`
	DASVIDToken					string `json:DASVIDToken",omitempty"`
	ZKP							string `json:ZKP",omitempty"`
}

type PocData struct {
	AccessToken     			string `json:",omitempty"`
	PublicKey					string `json:",omitempty"`
	OauthSigValidation 			*bool `json:",omitempty"`
	OauthExpValidation 			*bool `json:",omitempty"`
	OauthExpRemainingTime		string `json:",omitempty"`
	OauthClaims					map[string]interface{} `json:",omitempty"`
	DASVIDToken					string `json:",omitempty"`
	DASVIDClaims 				map[string]interface{} `json:",omitempty"`
	DasvidExpValidation 		*bool `json:",omitempty"`
	DasvidExpRemainingTime		string `json:",omitempty"`
	DasvidSigValidation 		*bool `json:",omitempty"`
		
}

var Data PocData
var Filetemp FileContents

const (
	socketPath    = "unix:///tmp/spire-agent/public/api.sock"
)

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s execution time is %s", name, elapsed)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	http.HandleFunc("/mint", MintHandler)
	http.HandleFunc("/keys", KeysHandler)
	http.HandleFunc("/validate", ValidateDasvidHandler)
	http.HandleFunc("/introspect", IntrospectHandler)

	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Printf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	// Allowed SPIFFE ID - Client must be from this trust domain
	clientID := spiffeid.RequireTrustDomainFromString("example.org")
	
	// Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match the allowed SPIFFE-ID
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(clientID))
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}
	
	log.Printf("Start serving API...")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Printf("Error on serve: %v", err)
	}
	
}

func KeysHandler(w http.ResponseWriter, r *http.Request) {
	
	defer timeTrack(time.Now(), "Keys")

	rsaPublicKey := dasvid.RetrieveJWKSPublicKey("./keys/jwks.json")

	json.NewEncoder(w).Encode(rsaPublicKey)
	
}

func MintHandler(w http.ResponseWriter, r *http.Request) {

	// TODO
	//  validate if oauth token issuer is known

	defer timeTrack(time.Now(), "Mint")

	sigresult := new(bool)
	expresult := new(bool)
	var remainingtime  string

	certs := r.TLS.PeerCertificates

	clientspiffeid, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		log.Printf("Error retrieving client SPIFFE-ID from mTLS connection %v", err)
	}
	log.Printf("Client SPIFFE-ID: %v", clientspiffeid)

	oauthtoken := r.FormValue("AccessToken")

	tokenclaims := dasvid.ParseTokenClaims(oauthtoken)
	*expresult, remainingtime = dasvid.ValidateTokenExp(tokenclaims)

	if *expresult == false {

		log.Printf("Oauth token expired!")

		Data = PocData{
			OauthExpValidation:		expresult,
			OauthExpRemainingTime:  remainingtime,
		}
		json.NewEncoder(w).Encode(Data)

	} else {

		// Retrieve Public Key from JWKS endpoint
		// 
		// OKTA pattern endpoint:
		// https://<Oauth token issuer>+"/v1/keys"
		// 
		// Google endpoint:
		// https://www.googleapis.com/oauth2/v3/certs

		log.Println("OAuth Issuer: ", tokenclaims["iss"])
		issuer := fmt.Sprintf("%v", tokenclaims["iss"])
		var uri string

		// TODO Add error handling
		if  issuer == "accounts.google.com" {
			log.Printf("Google OAuth token identified!")
			uri = "https://www.googleapis.com/oauth2/v3/certs"	
		} else {
			//  In this prototype we consider that if it is not a Google token its OKTA
			log.Printf("OKTA OAuth token identified!")
			uri = issuer+"/v1/keys"	
		}
		
		resp, err := http.Get(uri)
	
		defer resp.Body.Close()

		// Save response in cache file
		// TODO:
		// If the file exists it reuse or overwrite? It could be an old key...
		out, err := os.Create("./data/oauthjwkskey.cache")
		if err != nil {
			log.Printf("Error creating Oauth public key cache file: %v", err)
		}
		defer out.Close()
		io.Copy(out, resp.Body)

		// Read key from cache file
		pubkey := dasvid.RetrieveJWKSPublicKey("./data/oauthjwkskey.cache")
		// fmt.Println("Pubkey in main", pubkey.Keys[0])

		// Verify token signature using extracted Public key
		// //////////////////////////////////
		// TODO: create loop to test all keys in file
		//////////////////////////////////////
		err = dasvid.VerifySignature(oauthtoken, pubkey.Keys[0])
		if err != nil {

			log.Printf("Error verifying OAuth signature: %v", err)
			*sigresult = false

			Data = PocData{
				OauthExpValidation:		expresult,
				OauthExpRemainingTime:  remainingtime,
				OauthSigValidation:		sigresult,
			}

			json.NewEncoder(w).Encode(Data)
			
		} else {

			*sigresult = true
			
			// Fetch Asserting workload SVID to use as DASVID issuer
			assertingwl := dasvid.FetchX509SVID()

			// Generate DASVID claims
			iss := assertingwl.ID.String()
			sub := clientspiffeid.String()
			dpa := fmt.Sprintf("%v", tokenclaims["iss"])
			dpr := fmt.Sprintf("%v", tokenclaims["sub"])

			// Load private key from pem file used to sign DASVID
			awprivatekey := dasvid.RetrievePrivateKey("./keys/key.pem")

			// Generate DASVID
			token := dasvid.Mintdasvid(iss, sub, dpa, dpr, awprivatekey)

			// Gen ZKP
			zkp := dasvid.GenZKPproof(oauthtoken, pubkey.Keys[0])
			if zkp == "" {
				log.Println("Error generating ZKP proof")
			}
			// cvtzkp := (*C.rsa_sig_proof_t)(unsafe.Pointer(zkp))

			fmt.Println("Proof sucessfully created")
			fmt.Println("proof message: ", zkp)
			// fmt.Println("proof length: ", int(cvtzkp.len))
			// fmt.Println("proof p: ")
			// C.print_bn(*cvtzkp.p)
			// fmt.Println("proof c: ")
			// C.print_bn(*cvtzkp.c)			

			// rcvdb64, _ := dasvid.EncodeToBase64(cvtzkp.p)
			// printproof, err := base64.RawURLEncoding.DecodeString(rcvdb64)
			// fmt.Println(printproof)

			// Data to be returned in API 
			Data = PocData{
				OauthSigValidation: 		sigresult,
				OauthExpValidation:			expresult,
				OauthExpRemainingTime:  	remainingtime,
				DASVIDToken:	 			token,
			}

			// Data to be write in cache file
			Filetemp = FileContents{
				OauthToken:					oauthtoken,
				DASVIDToken:	 			token,
				ZKP:						zkp,
			}
			
			// About ZKP format:
			// 
			// proof = {length, bigP, bigC}
			// to save to file or inside DASVID
			// convert bigP and bigC to hex
			// 

			// Save token and ZKP (not implemented) in cache
			// If the file doesn't exist, create it, or append to the file
			f, err := os.OpenFile("./data/dasvid.data", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Writing to file...")
			json.NewEncoder(f).Encode(Filetemp)
			if err := f.Close(); err != nil {
				log.Fatal(err)
			}

			json.NewEncoder(w).Encode(Data)
		}
	}
}

func ValidateDasvidHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Validate")
	
	dasvidexpresult := new(bool)
	dasvidsigresult := new(bool)
	var remainingtime  string
	
	// Retrieve claims and validate token exp before signature validation
	datoken := r.FormValue("DASVID")
	dasvidclaims := dasvid.ParseTokenClaims(datoken)
	*dasvidexpresult, remainingtime = dasvid.ValidateTokenExp(dasvidclaims)

	// Retrieve Public Key from JWKS file
	// TODO Add error handling
	pubkey := dasvid.RetrieveJWKSPublicKey("./keys/jwks.json")
	// OR pubkey := dasvid.RetrievePublicKey("/keys/public.pem")

	// Verify token signature using extracted Public key
	err := dasvid.VerifySignature(datoken, pubkey.Keys[0])
	if err != nil {
		log.Printf("Error verifying DA-SVID signature: %v", err)
		*dasvidsigresult = false
	} else {
		*dasvidsigresult = true
	}
	
	Data = PocData{
		DasvidExpValidation: 	dasvidexpresult,
		DasvidExpRemainingTime: remainingtime,
		DasvidSigValidation:	dasvidsigresult,
		DASVIDClaims:			dasvidclaims,
	}

	json.NewEncoder(w).Encode(Data)
}

func IntrospectHandler(w http.ResponseWriter, r *http.Request) {

	defer timeTrack(time.Now(), "Introspect")
	
	// Retrieve claims and validate token exp before signature validation
	datoken := r.FormValue("DASVID")

	// Open dasvid cache file
	datafile, err := os.Open("./data/dasvid.data") 
	if err != nil {
		log.Fatal(err)
	}
	defer datafile.Close()

	// Iterate over lines looking for DASVID token
	scanner := bufio.NewScanner(datafile)

	for scanner.Scan() {

		json.Unmarshal([]byte(scanner.Text()), &Filetemp)
		if err != nil {
			log.Printf("error:", err)
		}
		
		if Filetemp.DASVIDToken == datoken {
			log.Println("DASVID ZKP identified!", Filetemp.ZKP )
			json.NewEncoder(w).Encode(Filetemp)
			return
		}
    }
    if scanner.Err() != nil {
        log.Printf("Error reading ZKP data file: %v", scanner.Err())
    }
	json.NewEncoder(w).Encode("DASVID not found")
}

