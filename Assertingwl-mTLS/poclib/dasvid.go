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
#include "rsa_sig_proof_util.h"

#cgo CFLAGS: -g -Wall -m64 -I${SRCDIR}/src
#cgo pkg-config: --static libssl libcrypto
#cgo LDFLAGS: -L${SRCDIR}/src

unsigned char sha256_der_encoding[] = 
    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
     0x05, 0x00, 0x04, 0x20, };

int rsa_msg_evp_extract_bn(BIGNUM **m, unsigned char *msg, unsigned int msg_len, EVP_PKEY *vkey) {
    int ret = 0, buf_len = 0;
    RSA *rsa = NULL;
    BIGNUM *n = NULL;
    unsigned char *buf = NULL;
    unsigned char *dig = NULL;
    unsigned char *enc = NULL;
    unsigned int dig_len = 0;
    unsigned int enc_len = 0;

    EVP_MD_CTX *mdctx;
    const EVP_MD* md = NULL;

    if(m == NULL || msg == NULL || vkey == NULL) {
        printf("Invalid parameters\n");
        return -1;
    }

    mdctx = EVP_MD_CTX_create();
    md = EVP_sha256();

    n = BN_new();
    rsa = EVP_PKEY_get1_RSA(vkey);

    if(rsa == NULL) {
        printf("Unable to read RSA key\n");
        ret = -1;
        goto msg_ext_err;
    }

    dig = (unsigned char *) OPENSSL_malloc(EVP_MD_size(md));
    if( EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, msg, msg_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, dig, &dig_len) != 1 ) {
        printf("Failed to hash message\n");
        ret = -1;
        goto msg_ext_err;
    }

    enc = (unsigned char *) OPENSSL_malloc(sizeof(sha256_der_encoding) + dig_len);
    memcpy(enc, sha256_der_encoding, sizeof(sha256_der_encoding));
    memcpy(enc + sizeof(sha256_der_encoding), dig, dig_len);
    enc_len = sizeof(sha256_der_encoding) + dig_len;

    BN_copy(n, RSA_get0_n(rsa));
    buf_len = BN_num_bytes(n);
    buf = OPENSSL_malloc(buf_len);
    RSA_padding_add_PKCS1_type_1(buf, buf_len, enc, enc_len);

    if(*m == NULL) *m = BN_new();
    if( BN_bin2bn(buf, buf_len, *m) == NULL ) {
        ret = -1;
        goto msg_ext_err;
    }

    return 1;

msg_ext_err:
    if(mdctx != NULL) EVP_MD_CTX_free(mdctx);
    if(*m != NULL) BN_free(*m);
    if(n != NULL) BN_free(n);
    if(buf != NULL) OPENSSL_free(buf);
    if(enc != NULL) OPENSSL_free(enc);

    return ret;
}

int rsa_sig_extract_bn(BIGNUM **s, unsigned char *sig, size_t sig_len) {
    int ret = 0;

    if(s == NULL || sig == NULL) {
        printf("Invalid parameters\n");
        return -1;
    }

    if(*s == NULL) *s = BN_new();

    if( BN_bin2bn(sig, sig_len, *s) == NULL ) {
        ret = -1;
        goto sig_ext_err;
    }

    return 1;

sig_ext_err:
    if(*s != NULL) BN_free(*s);

    return ret;
}

int rsa_vkey_extract_bn(BIGNUM **n, BIGNUM **e, EVP_PKEY *vkey) {
    int ret = 0;
    RSA *rsa = NULL;

    if(n == NULL || e == NULL || vkey == NULL) {
        printf("Invalid parameters\n");
        return -1;
    }

    if(*n == NULL) *n = BN_new();
    if(*e == NULL) *e = BN_new();

    rsa = EVP_PKEY_get1_RSA(vkey);

    if(rsa == NULL) {
        printf("Unable to read RSA key\n");
        ret = -1;
        goto vkey_ext_err;
    }

    BN_copy(*n, RSA_get0_n(rsa));
    BN_copy(*e, RSA_get0_e(rsa));

    if(*n == NULL || *e == NULL) {
        printf("Unable to extract RSA key\n");
        ret = -1;
        goto vkey_ext_err;
    }

    return 1;

vkey_ext_err:
    if(*n != NULL) BN_free(*n);
    if(*e != NULL) BN_free(*e);

    return ret;
}

rsa_sig_proof_t *rsa_sig_proof_new(int proof_len) {
    int i;
    rsa_sig_proof_t *proof = NULL;

    proof = (rsa_sig_proof_t *) OPENSSL_malloc(sizeof(rsa_sig_proof_t));
    proof->p = (BIGNUM **) OPENSSL_malloc(proof_len*sizeof(BIGNUM *));
    proof->c = (BIGNUM **) OPENSSL_malloc(proof_len*sizeof(BIGNUM *));
    proof->len = proof_len;

    for(i = 0; i < proof_len; i++) {
        proof->p[i] = BN_secure_new();
        proof->c[i] = BN_secure_new();
    }

    return proof;
}

void rsa_sig_proof_free(rsa_sig_proof_t *proof) {
    int i;

    if(proof == NULL) return;

    for(i = 0; i < proof->len; i++) {
        if(proof->p[i] != NULL) BN_free(proof->p[i]);
        if(proof->c[i] != NULL) BN_free(proof->c[i]);
    }

    OPENSSL_free(proof);
    proof = NULL;
}

rsa_sig_proof_t *rsa_sig_proof_prove(int sec_len, int proof_len, const BIGNUM *s, const BIGNUM *e,
                                     const BIGNUM *n) {
    int i;
    rsa_sig_proof_t *proof;

    BN_CTX *bnctx = NULL;
    EVP_MD_CTX* mdctx = NULL;
    const EVP_MD* md = NULL;

    unsigned char *c_bytes = NULL;
    unsigned char *b = NULL;
    unsigned int b_len = 0;

    proof = rsa_sig_proof_new(proof_len);

    bnctx = BN_CTX_secure_new();
    mdctx = EVP_MD_CTX_create();
    md = EVP_sha256();

    c_bytes = (unsigned char *) OPENSSL_malloc(sec_len);
    b = (unsigned char *) OPENSSL_malloc(EVP_MD_size(md));

    for(i = 0; i < proof_len; i++) {
        //r_i =R Zn
        if( BN_rand_range(proof->p[i], n) != 1 ) {
            printf("Failed to generate %d-th random\n", i);
            rsa_sig_proof_free(proof);
            goto proof_err;
        }

        //c_i = r_i^e : commitments
        BN_mod_exp(proof->c[i], proof->p[i], e, n, bnctx);
    }

    //b = hash(c_i, forall i)
    if( EVP_DigestInit_ex(mdctx, md, NULL) != 1 ) {
        printf("ERROR\n");
        rsa_sig_proof_free(proof);
        goto proof_err;
    }
    for(i = 0; i < proof_len; i++) {
        BN_bn2bin(proof->c[i], c_bytes);
        if( EVP_DigestUpdate(mdctx, c_bytes, BN_num_bytes(proof->c[i])) != 1 ) {
            printf("ERROR\n");
            rsa_sig_proof_free(proof);
            goto proof_err;
        }
    }
    if( EVP_DigestFinal_ex(mdctx, b, &b_len) != 1 ) {
        printf("ERROR\n");
        rsa_sig_proof_free(proof);
        goto proof_err;
    }

    for(i = 0; i < proof_len; i++) {
        if((b[i/8] >> (7-i%8)) &0x01) { //==1
            //open p_i = z_i = S r_i
            BN_mod_mul(proof->p[i], s, proof->p[i], n, bnctx);
        }
        else { //==0
            //open p_i = r_i (NOP)
        }
    }

proof_err:
    if(bnctx != NULL) BN_CTX_free(bnctx);
    if(mdctx != NULL) EVP_MD_CTX_free(mdctx);
    if(c_bytes != NULL) OPENSSL_free(c_bytes);
    if(b != NULL) OPENSSL_free(b);

    return proof;
}
 
int rsa_sig_proof_ver(rsa_sig_proof_t *proof, const BIGNUM *m, const BIGNUM *e, const BIGNUM *n) {
    int i, ret = -1;

    BN_CTX *bnctx = NULL;
    EVP_MD_CTX* mdctx = NULL;
    const EVP_MD* md = NULL;

    unsigned char *c_bytes = NULL;
    unsigned char *b = NULL;
    unsigned int b_len = 0;

    BIGNUM *f1, *f2;

    bnctx = BN_CTX_secure_new();
    mdctx = EVP_MD_CTX_create();
    md = EVP_sha256();

    c_bytes = (unsigned char *) OPENSSL_malloc(BN_num_bytes(n));
    b = (unsigned char *) OPENSSL_malloc(EVP_MD_size(md));

    f1 = BN_new();
    f2 = BN_new();

    //b = hash(c_i, forall i)
    if( EVP_DigestInit_ex(mdctx, md, NULL) != 1 ) {
        printf("ERROR\n");
        goto ver_err;
    }
    for(i = 0; i < proof->len; i++) {
        BN_bn2bin(proof->c[i], c_bytes);
        if( EVP_DigestUpdate(mdctx, c_bytes, BN_num_bytes(proof->c[i])) != 1 ) {
            printf("ERROR\n");
            goto ver_err;
        }
    }
    if( EVP_DigestFinal_ex(mdctx, b, &b_len) != 1 ) {
        printf("ERROR\n");
        goto ver_err;
    }

    for(i = 0; i < proof->len; i++) {
        BN_mod_exp(f1, proof->p[i], e, n, bnctx);
        if((b[i/8] >> (7-i%8)) &0x01) { //==1
            //assert p_i^e == M c_i
            BN_mod_mul(f2, m, proof->c[i], n, bnctx);
            if( BN_cmp(f1, f2) != 0 ) {
                ret = 0;
                goto ver_err;
            }
        }
        else { //==0
            BN_copy(f2, proof->c[i]);
            //assert p_i^e == c_i
            if( BN_cmp(f1, f2) != 0 ) {
                ret = 0;
                goto ver_err;
            }
        }
    }

    ret = 1;

ver_err:
    if(bnctx != NULL) BN_CTX_free(bnctx);
    if(mdctx != NULL) EVP_MD_CTX_free(mdctx);
    if(c_bytes != NULL) OPENSSL_free(c_bytes);
    if(b != NULL) OPENSSL_free(b);
    if(f1 != NULL) BN_free(f1);
    if(f2 != NULL) BN_free(f2);

    return ret;
}

rsa_sig_proof_t *rsa_evp_sig_proof_prove(int sec_len, int proof_len, unsigned char *sig,
                                         unsigned int sig_len, EVP_PKEY *vkey) {
    BIGNUM *n = NULL, *e = NULL, *s = NULL;

    if( rsa_vkey_extract_bn(&n, &e, vkey) != 1 ||
        rsa_sig_extract_bn(&s, sig, (size_t) sig_len) != 1 ) {
        return NULL;
    }

    return rsa_sig_proof_prove(sec_len, proof_len, s, e, n);
}

int rsa_evp_sig_proof_ver(rsa_sig_proof_t *proof, unsigned char *msg, unsigned int msg_len,
                          EVP_PKEY *vkey) {
    BIGNUM *n = NULL, *e = NULL, *m = NULL;

    if( rsa_vkey_extract_bn(&n, &e, vkey) != 1 ||
        rsa_msg_evp_extract_bn(&m, msg, msg_len, vkey) != 1 ) {
        return -1;
    }

    return rsa_sig_proof_ver(proof, m, e, n);
}

 void print_bn(BIGNUM *n) {
    int i;
    unsigned char *buf = NULL;

    if(n == NULL) {
        printf("NULL\n");
        return;
    }

    buf = (unsigned char *) OPENSSL_malloc(BN_num_bytes(n));

    BN_bn2bin(n, buf);

    for(i = 0; i < BN_num_bytes(n)-1; i++) {
        printf("%02X", buf[i]);
        if((i+1)%32 == 0) printf("\n");
        else if((i+1)%8 == 0) printf(" ");
    }
    printf("%02X\n", buf[BN_num_bytes(n)-1]);

    OPENSSL_free(buf);
 }

 int rsa_msg_extract_bn(BIGNUM **m, unsigned char *msg, unsigned int msg_len, BIGNUM *n) {
    int ret = 0, buf_len = 0;

    unsigned char *buf = NULL;
    unsigned char *dig = NULL;
    unsigned char *enc = NULL;

    unsigned int dig_len = 0;
    unsigned int enc_len = 0;

    EVP_MD_CTX *mdctx;
    const EVP_MD* md = NULL;


    if(m == NULL || msg == NULL || n == NULL) {
        printf("Invalid parameters\n");
        return -1;
    }

    mdctx = EVP_MD_CTX_create();
    md = EVP_sha256();

    dig = (unsigned char *) OPENSSL_malloc(EVP_MD_size(md));
    if( EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, msg, msg_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, dig, &dig_len) != 1 ) {
        printf("Failed to hash message\n");
        ret = -1;
        goto msg_ext_err;
    }

    enc = (unsigned char *) OPENSSL_malloc(sizeof(sha256_der_encoding) + dig_len);
    memcpy(enc, sha256_der_encoding, sizeof(sha256_der_encoding));
    memcpy(enc + sizeof(sha256_der_encoding), dig, dig_len);
    enc_len = sizeof(sha256_der_encoding) + dig_len;

	printf("\n enc generated: \n");

	for(int i = 0; i < enc_len; i++) {printf("%02x", enc[i]);}

	printf("\n end: \n");

    buf_len = BN_num_bytes(n);
    buf = OPENSSL_malloc(buf_len);
    RSA_padding_add_PKCS1_type_1(buf, buf_len, enc, enc_len);

    if(*m == NULL) *m = BN_new();
    if( BN_bin2bn(buf, buf_len, *m) == NULL ) {
        ret = -1;
        goto msg_ext_err;
    }

    return 1;

msg_ext_err:
    if(mdctx != NULL) EVP_MD_CTX_free(mdctx);
    if(*m != NULL) BN_free(*m);
    if(n != NULL) BN_free(n);
    if(buf != NULL) OPENSSL_free(buf);
    if(enc != NULL) OPENSSL_free(enc);

    return ret;
}

int rsa_bn_ver(const BIGNUM *s, const BIGNUM *m, const BIGNUM *n, const BIGNUM *e) {
    int ret = 0;
    BN_CTX *bnctx = NULL;
    BIGNUM *f = NULL;

    if(s == NULL || m == NULL || n == NULL || e == NULL) {
        printf("Invalid parameters to verify\n");
        return -1;
    }

    bnctx = BN_CTX_secure_new();
    f = BN_new();

    BN_mod_exp(f, s, e, n, bnctx);

    if( BN_cmp(f, m) == 0 ) {
        ret = 1;
    }

    BN_CTX_free(bnctx);

    return ret;
}


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
 		log.Fatalf("Error generating JWT: %v", err)
	}
 
	return tokenString
}

func ParseTokenClaims(strAT string) map[string]interface{} {

	defer timeTrack(time.Now(), "Parse token claims")

		// Parse access token without validating signature
		token, _, err := new(mint.Parser).ParseUnverified(strAT, mint.MapClaims{})
		if err != nil {
			log.Fatalf("Error parsing JWT claims: %v", err)
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
		log.Fatalf("Error opening private key file: %v", err)
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
		log.Fatalf("Error parsing private key: %v", err)
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
			fmt.Println("error", err)
		}
		
	default:
		fmt.Println("Unsupported key type %q", block.Type)
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
		log.Fatalf("Error opening public key file: %v", err)
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
			fmt.Println("error", err)
		}
		
	default:
		fmt.Println("Unsupported key type %q", block.Type)
	}

	// Return raw public key (N and E) (PEM)
	// return []byte(fmt.Sprint(publicKey))

	// Return DER
	marshpubic, _ := x509.MarshalPKIXPublicKey(publicKey)
    fmt.Println("Success returning DER: ", marshpubic)
	return marshpubic 
}

func RetrieveJWKSPublicKey(path string) JWKS {
	// Open file containing the keys obtained from /keys endpoint
	// NOTE: Needs to implement cache and retrieve processes
	jwksFile, err := os.Open(path)
	if err != nil {
		log.Fatalf("Error reading jwks file: %v", err)
	}

	// Decode file and retrieve Public key from Okta application
	dec := json.NewDecoder(jwksFile)
	var jwks JWKS
	
	if err := dec.Decode(&jwks); err != nil {
		log.Fatalf("Unable to read key: %s", err)
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
		log.Fatalf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		log.Fatalf("Unable to fetch SVID: %v", err)
	}

	return svid
}

func GenZKPproof(OAuthToken string, publickey JWK) int {

	defer timeTrack(time.Now(), "Generate ZKP")

	parts := strings.Split(OAuthToken, ".")

    var vkey *C.EVP_PKEY
    
	var bigN *C.BIGNUM
	bigN = C.BN_new()
    var bigE *C.BIGNUM
	bigE = C.BN_new()
    
    var filepem *C.FILE
    path := "./poclib/temp.der"
    filepem = C.fopen((C.CString)(path),(C.CString)("r")) 
  
    C.PEM_read_PUBKEY(filepem, &vkey, nil, nil)

    // Gen signature bignum
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		log.Fatalf("Error collecting signature: %v", err)
	}
	sig_len := len(signature)
	sig_C := C.CBytes(signature)
	defer C.free(unsafe.Pointer(sig_C))
	var bigSig *C.BIGNUM
	bigSig = C.BN_new()
	C.rsa_sig_extract_bn(&bigSig, (*C.uchar)(sig_C), (C.size_t)(sig_len))

	// Gen message Bignum
	message := []byte(strings.Join(parts[0:2], "."))
	msg_len := len(message)
	msg_C := C.CBytes(message)
	defer C.free(unsafe.Pointer(msg_C))
	var bigMsg *C.BIGNUM
	bigMsg = C.BN_new()
	bigmsgresult := C.rsa_msg_evp_extract_bn(&bigMsg, (*C.uchar)(msg_C), (C.uint)(msg_len), vkey)
	if bigmsgresult != 1 {
		fmt.Printf("Error generating bigMSG")
	}

    C.rsa_vkey_extract_bn(&bigN, &bigE, vkey)

	hasher := crypto.SHA256.New()
	hasher.Write(message)
	
	fmt.Println("\n*** Input data ***")
	fmt.Println("BigN: ")
	C.print_bn(bigN)
	fmt.Println("BigE: ")
	C.print_bn(bigE)
	fmt.Println("\nsig: ", signature)
	fmt.Println("sig_size: ", sig_len)
	fmt.Println("bigSig: ")
	C.print_bn(bigSig)	
	fmt.Println("message hash:  ", fmt.Sprintf("%x",hasher.Sum(nil)))
	fmt.Println("\nmessage: ", string(message))
	fmt.Println("msg_size: ", (C.uint)(msg_len))
	fmt.Println("BigMSG: ")
	C.print_bn(bigMsg)	

	sigver := C.rsa_bn_ver(bigSig, bigMsg, bigN, bigE)
	if( sigver == 0) {
        fmt.Println("Error in signature verification\n")
    }
	if( sigver == 1) {
        fmt.Println("Signature verification success!\n")
    }

	proof := C.rsa_sig_proof_prove(2048, 128, bigSig, bigE, bigN)
    
    if( proof == nil) {
        log.Fatal("Error creating proof\n")
    }

	fmt.Println("Proof sucessfully created")
	fmt.Println("proof: ", proof)
	fmt.Println("proof length: ", int(proof.len))
	fmt.Println("proof p: ")
	C.print_bn(*proof.p)
	fmt.Println("proof c: ")
	C.print_bn(*proof.c)

	
	// verification := C.rsa_evp_sig_proof_ver(proof, pmsg, (C.uint)(msg_len), key)
	verification := C.rsa_sig_proof_ver(proof, bigMsg, bigE, bigN)
    fmt.Println("Verification result: ", verification)
    
    C.EVP_PKEY_free(vkey);
    
    if( verification == 1) {
        log.Printf("Success verifying proof!!! :DDDD \n")
		return 1
    } else {
		log.Printf("Failed verifying proof :(( \n")
		return 0
	}


}