package dasvid
/*
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include "rsa_sig_proof.h"
#include "rsa_bn_sig.h"
#include "rsa_sig_proof_util.h"

#cgo CFLAGS: -g -Wall -m64 -I${SRCDIR}
#cgo pkg-config: --static libssl libcrypto
#cgo LDFLAGS: -L${SRCDIR}

*/
import "C"

import (

	"bytes"
	"strings"
	"encoding/base64"
	"fmt"
	"log"
	"unsafe"
		
	// To sig. validation 
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256"
	"encoding/binary"
	"math/big"

	"time"
	"os"
    "os/exec"
	"encoding/json"
		
	// // to retrieve PrivateKey
	"bufio"
	"crypto/x509"
    "encoding/pem"

	// To JWT generation
	mint "github.com/golang-jwt/jwt"
	"flag"

	// To fetch SVID
	"context"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
)

// Worload API socket path
const socketPath = "unix:///tmp/spire-agent/public/api.sock"
// set path to OAuth PEM public key file 
const path = "./keys/oauth.pem"

type SVID struct {
	// ID is the SPIFFE ID of the X509-SVID.
	ID spiffeid.ID

	// Certificates are the X.509 certificates of the X509-SVID. The leaf
	// certificate is the X509-SVID certificate. Any remaining certificates (
	// if any) chain the X509-SVID certificate back to a X.509 root for the
	// trust domain.
	Certificates []*x509.Certificate

	// PrivateKey is the private key for the X509-SVID.
	PrivateKey crypto.Signer
}

type X509Context struct {
	// SVIDs is a list of workload X509-SVIDs.
	SVIDs []*x509svid.SVID

	// Bundles is a set of X.509 bundles.
	Bundles *x509bundle.Set
}

type JWKS struct {
	Keys []JWK
}

type JWK struct {
	Alg string
	Kty string
	X5c []string
	N   string
	E   string
	Kid string
	X5t string
}

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s execution time is %s", name, elapsed)
}


func VerifySignature(jwtToken string, key JWK) error {

	defer timeTrack(time.Now(), "Verify Signature")

	parts := strings.Split(jwtToken, ".")
	message := []byte(strings.Join(parts[0:2], "."))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	n, _ := base64.RawURLEncoding.DecodeString(key.N)
	e, _ := base64.RawURLEncoding.DecodeString(key.E)
	z := new(big.Int)
	z.SetBytes(n)
	//decoding key.E returns a three byte slice, https://golang.org/pkg/encoding/binary/#Read and other conversions fail
	//since they are expecting to read as many bytes as the size of int being returned (4 bytes for uint32 for example)
	var buffer bytes.Buffer
	buffer.WriteByte(0)
	buffer.Write(e)
	exponent := binary.BigEndian.Uint32(buffer.Bytes())
	publicKey := &rsa.PublicKey{N: z, E: int(exponent)}

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed.
	hasher := crypto.SHA256.New()
	hasher.Write(message)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hasher.Sum(nil), signature)
	return err
}

func Mintdasvid(iss string, sub string, dpa string, dpr string, key interface{}) string{

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Set issue and exp time
	issue_time := time.Now().Round(0).Unix()
	exp_time := time.Now().Add(time.Minute * 2).Round(0).Unix()
 
	// Declaring flags
	issuer := flag.String("iss", iss, "issuer(iss) = SPIFFE ID of the workload that generated the DA-SVID (Asserting workload")
	assert := flag.Int64("aat", issue_time, "asserted at(aat) = time at which the assertion made in the DA-SVID was verified by the asserting workload")
	exp := flag.Int64("exp", exp_time, "expiration time(exp) = as small as reasonably possible, issue time + 1s by default.")
	subj := flag.String("sub", sub, "subject (sub) = the identity about which the assertion is being made. Subject workload's SPIFFE ID.")
	dlpa := flag.String("dpa", dpa, "delegated authority (dpa) = ")
	dlpr := flag.String("dpr", dpr, "delegated principal (dpr) = The Principal")
 
	flag.Parse()
 
	// Build Token
	token := mint.NewWithClaims(mint.SigningMethodRS256, mint.MapClaims{
		"exp": *exp,
		"iss": *issuer,
		"aat": *assert,
		"sub": *subj,
		"dpa": *dlpa,
		"dpr": *dlpr,
		"iat": issue_time,
	})
 
	// Sign Token
 	tokenString, err := token.SignedString(key)
 	if err != nil {
        log.Printf("Error generating JWT: %v", err)
	}
 
	return tokenString
}

func ParseTokenClaims(strAT string) map[string]interface{} {

	defer timeTrack(time.Now(), "Parse token claims")

		// Parse access token without validating signature
		token, _, err := new(mint.Parser).ParseUnverified(strAT, mint.MapClaims{})
		if err != nil {
			log.Printf("Error parsing JWT claims: %v", err)
		}
		claims, _ := token.Claims.(mint.MapClaims)
		
		// fmt.Println(claims)
		return claims
}

func ValidateTokenExp(claims map[string]interface{}) (expresult bool, remainingtime string) {

	defer timeTrack(time.Now(), "Validate token exp")

	tm := time.Unix(int64(claims["exp"].(float64)), 0)
	remaining := tm.Sub(time.Now())

	if remaining > 0 {
		expresult = true 
	} else {
		expresult = false
	}

	return expresult, remaining.String()

}

func RetrievePrivateKey(path string) interface{} {

	// Open file containing private Key
	privateKeyFile, err := os.Open(path)
	if err != nil {
		log.Printf("Error opening private key file: %v", err)
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	pemdata, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()

	// Extract Private Key 
	// updated to use RSA since key used will not be fetched from SPIRE
	privateKeyImported, err := x509.ParsePKCS1PrivateKey(pemdata.Bytes)
	if err != nil {
		log.Printf("Error parsing private key: %v", err)
	}
	return privateKeyImported
}

func RetrievePEMPublicKey(path string) interface{} {

	// Open file containing public Key
	publicKeyFile, err := os.Open(path)
	if err != nil {
		log.Fatalf("Error opening public key file: %v", err)
	}

	pemfileinfo, _ := publicKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)

	block, _ := pem.Decode(pembytes)
	if block == nil {
		log.Printf("No PEM key found: %v", err)
		// os.Exit(1)
	}

	var publicKey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Printf("error", err)
		}
		
	default:
		log.Printf("Unsupported key type %q", block.Type)
	}

	// Return raw public key (N and E) (PEM)
	return publicKey

	// Return DER
	// marshpubic, _ := x509.MarshalPKIXPublicKey(publicKey)
    // fmt.Println("Success returning DER: %x",marshpubic)
	// return marshpubic 
}

func RetrieveDERPublicKey(path string) []byte {

	// Open file containing public Key
	publicKeyFile, err := os.Open(path)
	if err != nil {
		log.Printf("Error opening public key file: %v", err)
	}

	pemfileinfo, _ := publicKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)

	block, _ := pem.Decode(pembytes)
	if block == nil {
		log.Printf("No key found: %v", err)
		// os.Exit(1)
	}

	var publicKey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Printf("error", err)
		}
		
	default:
		log.Printf("Unsupported key type %q", block.Type)
	}

	// Return raw public key (N and E) (PEM)
	// return []byte(fmt.Sprint(publicKey))

	// Return DER
	marshpubic, _ := x509.MarshalPKIXPublicKey(publicKey)
    // log.Printf("Success returning DER: ", marshpubic)
	return marshpubic 
}

func RetrieveJWKSPublicKey(path string) JWKS {
	// Open file containing the keys obtained from /keys endpoint
	// NOTE: Needs to implement cache and retrieve processes
	jwksFile, err := os.Open(path)
	if err != nil {
		log.Printf("Error reading jwks file: %v", err)
	}

	// Decode file and retrieve Public key from Okta application
	dec := json.NewDecoder(jwksFile)
	var jwks JWKS
	
	if err := dec.Decode(&jwks); err != nil {
		log.Printf("Unable to read key: %s", err)
	}

	return jwks
}

func FetchX509SVID() *x509svid.SVID {

	defer timeTrack(time.Now(), "Fetchx509svid")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Printf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		log.Printf("Unable to fetch SVID: %v", err)
	}

	return svid
}

func GenZKPproof(OAuthToken string, publickey JWK) int {

	defer timeTrack(time.Now(), "Generate ZKP")

    var vkey *C.EVP_PKEY
    var bigN, bigE, bigSig, bigMsg *C.BIGNUM
    var filepem *C.FILE

    parts := strings.Split(OAuthToken, ".")

    // extract token issuer
    tokenclaims := ParseTokenClaims(OAuthToken)
    issuer := fmt.Sprintf("%v", tokenclaims["iss"])
    // Considering its OKTA based solution, add /keys endpoint
    keyEndPoint := issuer+"/v1/keys"

    // Use script to convert jwk retrieved from OKTA endpoint to DER
    // PEM file will be saved in ./keys/
    cmd := exec.Command("./poclib/jwk2der.sh", keyEndPoint)
    err := cmd.Run()
    if err != nil {
        log.Fatal(err)
    }

    // Open OAuth PEM file containing Public Key
    filepem = C.fopen((C.CString)(path),(C.CString)("r")) 
  
    // Load key from PEM file to VKEY
    C.PEM_read_PUBKEY(filepem, &vkey, nil, nil)

    // Extract token signature and generate signature BIGNUM
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		log.Printf("Error collecting signature: %v", err)
	}
	sig_len := len(signature)
	sig_C := C.CBytes(signature)
	defer C.free(unsafe.Pointer(sig_C))
	
	bigSig = C.BN_new()
	C.rsa_sig_extract_bn(&bigSig, (*C.uchar)(sig_C), (C.size_t)(sig_len))

	// Gen message BIGNUM
	message := []byte(strings.Join(parts[0:2], "."))
	msg_len := len(message)
	msg_C := C.CBytes(message)
	defer C.free(unsafe.Pointer(msg_C))
	
	bigMsg = C.BN_new()
	bigmsgresult := C.rsa_msg_evp_extract_bn(&bigMsg, (*C.uchar)(msg_C), (C.uint)(msg_len), vkey)
	if bigmsgresult != 1 {
		log.Printf("Error generating bigMSG")
	}

    // Extract bigN and bigE from VKEY
    bigN = C.BN_new()
	bigE = C.BN_new()
    C.rsa_vkey_extract_bn(&bigN, &bigE, vkey)
    C.EVP_PKEY_free(vkey)

    // -=-=-=-=-= DEBUG -=-=-=-=-=-
	// Generate message hash
    // hasher := crypto.SHA256.New()
	// hasher.Write(message)
	
	// fmt.Println("\n*** Input data ***")
	// fmt.Println("BigN: ")
	// C.print_bn(bigN)
	// fmt.Println("BigE: ")
	// C.print_bn(bigE)
	// fmt.Println("\nsig: ", signature)
	// fmt.Println("sig_size: ", sig_len)
	// fmt.Println("bigSig: ")
	// C.print_bn(bigSig)	
	// fmt.Println("message hash:  ", fmt.Sprintf("%x",hasher.Sum(nil)))
	// fmt.Println("\nmessage: ", string(message))
	// fmt.Println("msg_size: ", (C.uint)(msg_len))
	// fmt.Println("BigMSG: ")
	// C.print_bn(bigMsg)	
    // -=-=-=-=-=-=-=-=-=-=-=-=-=-=- 

    // Verify signature correctness 
	sigver := C.rsa_bn_ver(bigSig, bigMsg, bigN, bigE)
	if( sigver == 0) {
        log.Printf("Error in signature verification\n")
    }
	if( sigver == 1) {
        log.Printf("Signature verification success!\n")
    }

    // Generate Zero Knowledge Proof
	proof := C.rsa_sig_proof_prove(2048, 128, bigSig, bigE, bigN)
    if( proof == nil) {
        log.Printf("Error creating proof\n")
    }

	// -=-=-=- DEBUG -=-=-=-=-
    // fmt.Println("Proof sucessfully created")
	// fmt.Println("proof: ", proof)
	// fmt.Println("proof length: ", int(proof.len))
	// fmt.Println("proof p: ")
	// C.print_bn(*proof.p)
	// fmt.Println("proof c: ")
	// C.print_bn(*proof.c)
    // -=-=-=-=-=-=-=-=-=-=-=-

	// Check proof correctness
	verification := C.rsa_sig_proof_ver(proof, bigMsg, bigE, bigN)
    var ret int
    if( verification == 1) {
        log.Printf("Success verifying proof!!! :DD \n")
		ret = 1
    } else if( verification == 0) {
		log.Printf("Failed verifying proof :(( \n")
		ret = 0
	} else if( verification == -1) {
        log.Printf("Error verifying proof :(( \n")
		ret = -1
    }
    return ret
}