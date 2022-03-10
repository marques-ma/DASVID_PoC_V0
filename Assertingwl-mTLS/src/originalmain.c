#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "rsa_sig_proof.h"
#include "rsa_evp_sig.h"
#include "rsa_bn_sig.h"
#include "rsa_sig_proof_util.h"

/* tests */
int test_evp_sig(void);
int test_bn_sig(void);
int test_compare_evp_bn(void);
int test_rsa_proof(void);
int test_evp_rsa_proof(void);
int test_rsa_proof_fail1(void);
int test_rsa_proof_fail2(void);
int test_evp_rsa_proof_fail1(void);
int test_evp_rsa_proof_fail2(void);

int main(int argc, char *argv[]) {
    int i, err, sample = 0;

    if(argc > 2) {
        printf("Please, use only one argument\n");
        return 1;
    }
    if(argc == 2) {
        sample = strtol(argv[1], NULL, 10);
        if(sample <= 0)
            sample = 1;
    }

    printf("**Testing EVP signing:\n");
    err = 0;
    for(i = 0; i < sample; i++) {
        if(test_evp_sig() != 1) err++;
    }
    printf("Tests resulted in %d/%d errors.\n", err, sample);

    printf("**Testing BN signing:\n");
    err = 0;
    for(i = 0; i < sample; i++) {
        if(test_bn_sig() != 1) err++;
    }
    printf("Tests resulted in %d/%d errors.\n", err, sample);

    printf("**Comparing BN and EVP signatures:\n");
    err = 0;
    for(i = 0; i < sample; i++) {
        if(test_compare_evp_bn() != 1) err++;
    }
    printf("Tests resulted in %d/%d errors.\n", err, sample);

    printf("**Testing RSA proof:\n");
    err = 0;
    for(i = 0; i < sample; i++) {
        if(test_rsa_proof() != 1) err++;
    }
    printf("Tests resulted in %d/%d errors.\n", err, sample);

    printf("**Testing RSA proof with EVP signing:\n");
    err = 0;
    for(i = 0; i < sample; i++) {
        if(test_evp_rsa_proof() != 1) err++;
    }
    printf("Tests resulted in %d/%d errors.\n", err, sample);

    printf("**Testing wrong RSA proof #1:\n");
    err = 0;
    for(i = 0; i < sample; i++) {
        if(test_rsa_proof_fail1() != 1) err++;
    }
    printf("Tests resulted in %d/%d errors.\n", err, sample);

    printf("**Testing wrong RSA proof #2:\n");
    err = 0;
    for(i = 0; i < sample; i++) {
        if(test_rsa_proof_fail2() != 1) err++;
    }
    printf("Tests resulted in %d/%d errors.\n", err, sample);

    printf("**Testing wrong RSA proof with EVP signing #1:\n");
    err = 0;
    for(i = 0; i < sample; i++) {
        if(test_evp_rsa_proof_fail1() != 1) err++;
    }
    printf("Tests resulted in %d/%d errors.\n", err, sample);

    printf("**Testing wrong RSA proof with EVP signing #2:\n");
    err = 0;
    for(i = 0; i < sample; i++) {
        if(test_evp_rsa_proof_fail2() != 1) err++;
    }
    printf("Tests resulted in %d/%d errors.\n", err, sample);

    return 0;
}

/**
 * This test verify the correctness of generating RSA keys, signing a message, and verifying the
 * signature, using the EVP interface from OpenSSL library. The message digest used is SHA256.
 */
int test_evp_sig(void) {
    int ret = 0, sec_len = 2048;

    EVP_PKEY *skey = NULL, *vkey = NULL;

    size_t sig_len = 0;
    unsigned char *sig = NULL;

    unsigned char msg[] = "Just some random message";
    unsigned int msg_len = 0;

    msg_len = sizeof(msg);

    /* generate keys */
    if( rsa_evp_keygen(&skey, &vkey, sec_len) != 1 ) {
        printf("Error generating RSA keys\n");
        ret = -1;
        goto evp_err;
    }

    /* sign */
    if( rsa_evp_sign(&sig, &sig_len, msg, msg_len, skey) != 1) {
        printf("Error signing with RSA\n");
        ret = -1;
        goto evp_err;
    }

    /* verify */
    if( rsa_evp_verify(sig, sig_len, msg, msg_len, vkey) != 1) {
        printf("Error verifying RSA signature\n");
        ret = -1;
        goto evp_err;
    }

    // printf("**[OK]\n");
    ret = 1;

evp_err:
    if(skey != NULL) EVP_PKEY_free(skey);
    if(vkey != NULL) EVP_PKEY_free(vkey);
    if(sig != NULL) OPENSSL_free(sig);

    return ret;
}

/**
 * This test emulates the textbook RSA signature algorithm, when considering that both the message
 * and the signature are BIGNUM.
 */
int test_bn_sig(void) {
    int ret = 0, sec_len = 2048;

    EVP_PKEY *skey = NULL, *vkey = NULL;

    BN_CTX *bnctx = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *m = NULL, *s = NULL;

    bnctx = BN_CTX_secure_new();

    /* generate keys */
    if( rsa_evp_keygen(&skey, &vkey, sec_len) != 1 ) {
        printf("Error generating RSA keys\n");
        ret = -1;
        goto bn_err;
    }

    /* extract keys */
    if( rsa_vkey_extract_bn(&n, &e, vkey) != 1 ||
        rsa_skey_extract_bn(&d, skey) != 1 ) {
        printf("Failed to extract key\n");
        ret = -1;
        goto bn_err;
    }

    m = BN_new();
    BN_rand_range(m, n);

    /* sign */
    s = rsa_bn_sig(m, n, d);
    if(s == NULL) {
        printf("Error signing\n");
        ret = -1;
        goto bn_err;
    }

    /* verify */
    if( rsa_bn_ver(s, m, n, e) != 1 ) {
        printf("Error verifying\n");
        ret = -1;
        goto bn_err;
    }

    // printf("**[OK]\n");
    ret = 1;

bn_err:
    if(bnctx != NULL) BN_CTX_free(bnctx);
    if(skey != NULL) EVP_PKEY_free(skey);
    if(vkey != NULL) EVP_PKEY_free(vkey);
    if(n != NULL) BN_free(n);
    if(e != NULL) BN_free(e);
    if(d != NULL) BN_free(d);
    if(m != NULL) BN_free(m);
    if(s != NULL) BN_free(s);

    return ret;
}

/**
 * This test compares that both the signature generation using OpenSSL's EVP interface (with
 * SHA256 message digest) and the textbook RSA signing algorithm produces the same signature. The
 * objective was to verify that the proposed methods to extract a BIGNUM from a messsage or
 * signature are valid.
 */
int test_compare_evp_bn(void) {
    int ret = 0, sec_len = 2048;

    EVP_PKEY *skey = NULL, *vkey = NULL;

    BN_CTX *bnctx = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *m = NULL, *s = NULL, *s2 = NULL;

    size_t sig_len = 0;
    unsigned char *sig = NULL;

    unsigned char msg[] = "Just some random message";
    unsigned int msg_len = 0;

    msg_len = sizeof(msg);

    bnctx = BN_CTX_secure_new();

    /* generate keys */
    if( rsa_evp_keygen(&skey, &vkey, sec_len) != 1 ) {
        printf("Error generating RSA keys\n");
        ret = -1;
        goto comp_err;
    }

    /* extract keys */
    if( rsa_vkey_extract_bn(&n, &e, vkey) != 1 ||
        rsa_skey_extract_bn(&d, skey) != 1 ) {
        printf("Failed to extract key\n");
        ret = -1;
        goto comp_err;
    }

    /* extract messages */
    if( rsa_msg_extract_bn(&m, msg, msg_len, vkey) != 1 ) {
        printf("Failed to extract message\n");
        ret = -1;
        goto comp_err;
    }

    /* sign */
    if( rsa_evp_sign(&sig, &sig_len, msg, msg_len, skey) != 1) {
        printf("Error signing with RSA\n");
        ret = -1;
        goto comp_err;
    }

    /* verify */
    if( rsa_evp_verify(sig, sig_len, msg, msg_len, vkey) != 1) {
        printf("Error verifying RSA signature\n");
        ret = -1;
        goto comp_err;
    }

    /* extract signature */
    if( rsa_sig_extract_bn(&s, sig, sig_len) != 1 ) {
        printf("Failed to extract signature\n");
        ret = -1;
        goto comp_err;
    }

    /* sign */
    s2 = rsa_bn_sig(m, n, d);
    if(s2 == NULL) {
        printf("Error signing\n");
        ret = -1;
        goto comp_err;
    }

    /* verify */
    if( rsa_bn_ver(s2, m, n, e) != 1 ) {
        printf("Error verifying\n");
        ret = -1;
        goto comp_err;
    }

    /* compare */
    if( BN_cmp(s, s2) != 0 ) {
        printf("ERROR: different signatures\n");
        ret = -1;
        goto comp_err;
    }

    // printf("**[OK]\n");
    ret = 1;

comp_err:
    if(bnctx != NULL) BN_CTX_free(bnctx);
    if(skey != NULL) EVP_PKEY_free(skey);
    if(vkey != NULL) EVP_PKEY_free(vkey);
    if(sig != NULL) OPENSSL_free(sig);
    if(n != NULL) BN_free(n);
    if(e != NULL) BN_free(e);
    if(d != NULL) BN_free(d);
    if(m != NULL) BN_free(m);
    if(s != NULL) BN_free(s);

    return ret;
}

/**
 * This test verifies that a proof that a user has an RSA signature can be correctly generated and
 * verified. This method considers the textbook RSA signature, where messages and signatures are
 * BIGNUM.
 */
int test_rsa_proof(void) {
    int ret = 0, sec_len = 2048, proof_len = 128;

    EVP_PKEY *skey = NULL, *vkey = NULL;

    BN_CTX *bnctx = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *m = NULL, *s = NULL;

    rsa_sig_proof_t *proof = NULL;

    bnctx = BN_CTX_secure_new();

    /* generate keys */
    if( rsa_evp_keygen(&skey, &vkey, sec_len) != 1 ) {
        printf("Error generating RSA keys\n");
        ret = -1;
        goto proof_err;
    }

    /* extract keys */
    if( rsa_vkey_extract_bn(&n, &e, vkey) != 1 ||
        rsa_skey_extract_bn(&d, skey) != 1 ) {
        printf("Failed to extract key\n");
        ret = -1;
        goto proof_err;
    }

    m = BN_new();
    BN_rand_range(m, n);

    /* sign */
    s = rsa_bn_sig(m, n, d);
    if(s == NULL) {
        printf("Error signing\n");
        ret = -1;
        goto proof_err;
    }

    /* verify */
    if( rsa_bn_ver(s, m, n, e) != 1 ) {
        printf("Error verifying\n");
        ret = -1;
        goto proof_err;
    }

    /* prove */
    proof = rsa_sig_proof_prove(sec_len, proof_len, s, e, n);
    if( proof == NULL) {
        printf("Error creating proof\n");
        ret = -1;
        goto proof_err;
    }

    /* verify proof */
    if( rsa_sig_proof_ver(proof, m, e, n) != 1) {
        printf("Error verifying proof\n");
        ret = -1;
        goto proof_err;
    }

    // printf("**[OK]\n");
    ret = 1;

proof_err:
    if(bnctx != NULL) BN_CTX_free(bnctx);
    if(skey != NULL) EVP_PKEY_free(skey);
    if(vkey != NULL) EVP_PKEY_free(vkey);
    if(n != NULL) BN_free(n);
    if(e != NULL) BN_free(e);
    if(d != NULL) BN_free(d);
    if(m != NULL) BN_free(m);
    if(s != NULL) BN_free(s);
    if(proof != NULL) rsa_sig_proof_free(proof);

    return ret;
}

/**
 * This test verifies that a proof that a user has an RSA signature can be correctly generated and
 * verified. This method considers the signature generated by OpenSSL's EVP interface.
 */
int test_evp_rsa_proof(void) {
    int ret = 0, sec_len = 2048, proof_len = 128;

    EVP_PKEY *skey = NULL, *vkey = NULL;

    size_t sig_len = 0;
    unsigned char *sig = NULL;

    rsa_sig_proof_t *proof = NULL;

    unsigned char msg[] = "Just some random message";
    unsigned int msg_len = 0;

    msg_len = sizeof(msg);

    /* generate keys */
    if( rsa_evp_keygen(&skey, &vkey, sec_len) != 1 ) {
        printf("Error generating RSA keys\n");
        ret = -1;
        goto evp_proof_err;
    }

    /* sign */
    if( rsa_evp_sign(&sig, &sig_len, msg, msg_len, skey) != 1) {
        printf("Error signing with RSA\n");
        ret = -1;
        goto evp_proof_err;
    }

    /* verify */
    if( rsa_evp_verify(sig, sig_len, msg, msg_len, vkey) != 1) {
        printf("Error verifying RSA signature\n");
        ret = -1;
        goto evp_proof_err;
    }

    /* prove */
    proof = rsa_evp_sig_proof_prove(sec_len, proof_len, sig, sig_len, vkey);
    if( proof == NULL) {
        printf("Error creating proof\n");
        ret = -1;
        goto evp_proof_err;
    }

    /* verify proof */
    if( rsa_evp_sig_proof_ver(proof, msg, msg_len, vkey) != 1 ) {
        printf("Error verifying proof\n");
        ret = -1;
        goto evp_proof_err;
    }

    // printf("**[OK]\n");
    ret = 1;

evp_proof_err:
    if(skey != NULL) EVP_PKEY_free(skey);
    if(vkey != NULL) EVP_PKEY_free(vkey);
    if(sig != NULL) OPENSSL_free(sig);
    if(proof != NULL) rsa_sig_proof_free(proof);

    return ret;
}

/**
 * This test tries to subvert the proof by attempting to verify a proof with a (random) message
 * not related to the signature used when proving. It is expected that the verification fails.
 * It considers that textbook RSA with message and signature with BIGNUM.
 */
int test_rsa_proof_fail1(void) {
    int ret = 0, sec_len = 2048, proof_len = 128;

    EVP_PKEY *skey = NULL, *vkey = NULL;

    BN_CTX *bnctx = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *m = NULL, *m2 = NULL, *s = NULL;

    rsa_sig_proof_t *proof = NULL;

    bnctx = BN_CTX_secure_new();

    /* generate keys */
    if( rsa_evp_keygen(&skey, &vkey, sec_len) != 1 ) {
        printf("Error generating RSA keys\n");
        ret = -1;
        goto proof_fail1_err;
    }

    /* extract keys */
    if( rsa_vkey_extract_bn(&n, &e, vkey) != 1 ||
        rsa_skey_extract_bn(&d, skey) != 1 ) {
        printf("Failed to extract key\n");
        ret = -1;
        goto proof_fail1_err;
    }

    m = BN_new();
    BN_rand_range(m, n);

    /* sign */
    s = rsa_bn_sig(m, n, d);
    if(s == NULL) {
        printf("Error signing\n");
        ret = -1;
        goto proof_fail1_err;
    }

    /* verify */
    if( rsa_bn_ver(s, m, n, e) != 1 ) {
        printf("Error verifying\n");
        ret = -1;
        goto proof_fail1_err;
    }

    /* prove */
    proof = rsa_sig_proof_prove(sec_len, proof_len, s, e, n);
    if( proof == NULL) {
        printf("Error creating proof\n");
        ret = -1;
        goto proof_fail1_err;
    }

    /* verify proof */
    if( rsa_sig_proof_ver(proof, m, e, n) != 1) {
        printf("Error verifying proof\n");
        ret = -1;
        goto proof_fail1_err;
    }

    /* get other random message */
    m2 = BN_new();
    BN_rand_range(m2, n);

    /* (fail to) verify proof */
    if( rsa_sig_proof_ver(proof, m2, e, n) == 1) {
        printf("Accepted a wrong proof\n");
        ret = -1;
        goto proof_fail1_err;
    }

    // printf("**[OK]\n");
    ret = 1;

proof_fail1_err:
    if(bnctx != NULL) BN_CTX_free(bnctx);
    if(skey != NULL) EVP_PKEY_free(skey);
    if(vkey != NULL) EVP_PKEY_free(vkey);
    if(n != NULL) BN_free(n);
    if(e != NULL) BN_free(e);
    if(d != NULL) BN_free(d);
    if(m != NULL) BN_free(m);
    if(m2 != NULL) BN_free(m2);
    if(s != NULL) BN_free(s);
    if(proof != NULL) rsa_sig_proof_free(proof);

    return ret;
}

/**
 * This test tries to subvert the proof by attempting to verify a proof with a component modified,
 * so that this proof was not correctly generated to the message. It is expected that the 
 * verification fails. It considers that textbook RSA with message and signature with BIGNUM.
 */
int test_rsa_proof_fail2(void) {
    int ret = 0, sec_len = 2048, proof_len = 128;

    EVP_PKEY *skey = NULL, *vkey = NULL;

    BN_CTX *bnctx = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    BIGNUM *m = NULL, *s = NULL;

    rsa_sig_proof_t *proof = NULL;

    bnctx = BN_CTX_secure_new();

    /* generate keys */
    if( rsa_evp_keygen(&skey, &vkey, sec_len) != 1 ) {
        printf("Error generating RSA keys\n");
        ret = -1;
        goto proof_fail2_err;
    }

    /* extract keys */
    if( rsa_vkey_extract_bn(&n, &e, vkey) != 1 ||
        rsa_skey_extract_bn(&d, skey) != 1 ) {
        printf("Failed to extract key\n");
        ret = -1;
        goto proof_fail2_err;
    }

    m = BN_new();
    BN_rand_range(m, n);

    /* sign */
    s = rsa_bn_sig(m, n, d);
    if(s == NULL) {
        printf("Error signing\n");
        ret = -1;
        goto proof_fail2_err;
    }

    /* verify */
    if( rsa_bn_ver(s, m, n, e) != 1 ) {
        printf("Error verifying\n");
        ret = -1;
        goto proof_fail2_err;
    }

    /* prove */
    proof = rsa_sig_proof_prove(sec_len, proof_len, s, e, n);
    if( proof == NULL) {
        printf("Error creating proof\n");
        ret = -1;
        goto proof_fail2_err;
    }

    /* verify proof */
    if( rsa_sig_proof_ver(proof, m, e, n) != 1) {
        printf("Error verifying proof\n");
        ret = -1;
        goto proof_fail2_err;
    }

    /* change proof */
    BN_rand_range(proof->p[42], n);

    /* (fail to) verify proof */
    if( rsa_sig_proof_ver(proof, m, e, n) == 1) {
        printf("Accepted a wrong proof\n");
        ret = -1;
        goto proof_fail2_err;
    }

    // printf("**[OK]\n");
    ret = 1;

proof_fail2_err:
    if(bnctx != NULL) BN_CTX_free(bnctx);
    if(skey != NULL) EVP_PKEY_free(skey);
    if(vkey != NULL) EVP_PKEY_free(vkey);
    if(n != NULL) BN_free(n);
    if(e != NULL) BN_free(e);
    if(d != NULL) BN_free(d);
    if(m != NULL) BN_free(m);
    if(s != NULL) BN_free(s);
    if(proof != NULL) rsa_sig_proof_free(proof);

    return ret;
}

/**
 * This test tries to subvert the proof by attempting to verify a proof with a (random) message
 * not related to the signature used when proving. It is expected that the verification fails.
 * It considers that signature generated by the OpenSSL's EVP interface (with SHA256 message
 * digest).
 */
int test_evp_rsa_proof_fail1(void) {
    int ret = 0, sec_len = 2048, proof_len = 128;

    EVP_PKEY *skey = NULL, *vkey = NULL;

    size_t sig_len = 0;
    unsigned char *sig = NULL;

    rsa_sig_proof_t *proof = NULL;

    unsigned char msg[] = "Just some random message";
    unsigned int msg_len = 0;

    unsigned char other[] = "Just another random message";
    unsigned int other_len = 0;

    msg_len = sizeof(msg);
    other_len = sizeof(other);

    /* generate keys */
    if( rsa_evp_keygen(&skey, &vkey, sec_len) != 1 ) {
        printf("Error generating RSA keys\n");
        ret = -1;
        goto evp_proof_fail1_err;
    }

    /* sign */
    if( rsa_evp_sign(&sig, &sig_len, msg, msg_len, skey) != 1) {
        printf("Error signing with RSA\n");
        ret = -1;
        goto evp_proof_fail1_err;
    }

    /* verify */
    if( rsa_evp_verify(sig, sig_len, msg, msg_len, vkey) != 1) {
        printf("Error verifying RSA signature\n");
        ret = -1;
        goto evp_proof_fail1_err;
    }

    /* prove */
    proof = rsa_evp_sig_proof_prove(sec_len, proof_len, sig, sig_len, vkey);
    if( proof == NULL) {
        printf("Error creating proof\n");
        ret = -1;
        goto evp_proof_fail1_err;
    }

    /* verify proof */
    if( rsa_evp_sig_proof_ver(proof, msg, msg_len, vkey) != 1 ) {
        printf("Error verifying proof\n");
        ret = -1;
        goto evp_proof_fail1_err;
    }

    /* (fail to) verify proof */
    if( rsa_evp_sig_proof_ver(proof, other, other_len, vkey) == 1 ) {
        printf("Accepted a wrong proof\n");
        ret = -1;
        goto evp_proof_fail1_err;
    }

    // printf("**[OK]\n");
    ret = 1;

evp_proof_fail1_err:
    if(skey != NULL) EVP_PKEY_free(skey);
    if(vkey != NULL) EVP_PKEY_free(vkey);
    if(sig != NULL) OPENSSL_free(sig);
    if(proof != NULL) rsa_sig_proof_free(proof);

    return ret;
}

/**
 * This test tries to subvert the proof by attempting to verify a proof with a component modified,
 * so that this proof was not correctly generated to the message. It is expected that the 
 * verification fails. It considers that signature generated by the OpenSSL's EVP interface (with
 * SHA256 message digest).
 */
int test_evp_rsa_proof_fail2(void) {
    int ret = 0, sec_len = 2048, proof_len = 128;

    BIGNUM *n = NULL, *e = NULL;
    EVP_PKEY *skey = NULL, *vkey = NULL;

    size_t sig_len = 0;
    unsigned char *sig = NULL;

    rsa_sig_proof_t *proof = NULL;

    unsigned char msg[] = "Just some random message";
    unsigned int msg_len = 0;

    msg_len = sizeof(msg);

    /* generate keys */
    if( rsa_evp_keygen(&skey, &vkey, sec_len) != 1 ) {
        printf("Error generating RSA keys\n");
        ret = -1;
        goto evp_proof_fail2_err;
    }

    /* sign */
    if( rsa_evp_sign(&sig, &sig_len, msg, msg_len, skey) != 1) {
        printf("Error signing with RSA\n");
        ret = -1;
        goto evp_proof_fail2_err;
    }

    /* verify */
    if( rsa_evp_verify(sig, sig_len, msg, msg_len, vkey) != 1) {
        printf("Error verifying RSA signature\n");
        ret = -1;
        goto evp_proof_fail2_err;
    }

    /* prove */
    proof = rsa_evp_sig_proof_prove(sec_len, proof_len, sig, sig_len, vkey);
    if( proof == NULL) {
        printf("Error creating proof\n");
        ret = -1;
        goto evp_proof_fail2_err;
    }

    /* verify proof */
    if( rsa_evp_sig_proof_ver(proof, msg, msg_len, vkey) != 1 ) {
        printf("Error verifying proof\n");
        ret = -1;
        goto evp_proof_fail2_err;
    }

    /* change proof */
    rsa_vkey_extract_bn(&n, &e, vkey);
    BN_rand_range(proof->p[0], n);

    /* (fail to) verify proof */
    if( rsa_evp_sig_proof_ver(proof, msg, msg_len, vkey) == 1 ) {
        printf("Accepted a wrong proof\n");
        ret = -1;
        goto evp_proof_fail2_err;
    }

    // printf("**[OK]\n");
    ret = 1;

evp_proof_fail2_err:
    if(skey != NULL) EVP_PKEY_free(skey);
    if(vkey != NULL) EVP_PKEY_free(vkey);
    if(sig != NULL) OPENSSL_free(sig);
    if(proof != NULL) rsa_sig_proof_free(proof);
    if(n != NULL) BN_free(n);
    if(e != NULL) BN_free(e);

    return ret;
}



/* implementation */

/* everything is ASN.1/DER encoded, such as signature and digests */

/* BIO_ interface is an I/O stream abstraction (crypto/bio)
 * source/sink BIO to read and write
 * filter BIO to process */