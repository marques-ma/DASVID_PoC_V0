# makefile for a proof of ownership of a RSA signature
# it considers that openssl is installed in the standard path

CC=gcc
CFLAGS+=-g -Wall -m64 -I. -L.
CFLAGS+=-lssl -lcrypto

DEPS=rsa_sig_proof.h rsa_evp_sig.h rsa_bn_sig.h rsa_sig_proof_util.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

zkp-rsa: main.o rsa_sig_proof.o rsa_evp_sig.o rsa_bn_sig.o rsa_sig_proof_util.o
	$(CC) -o $@ $^ $(CFLAGS)

all: zkp-rsa

clean:
	rm *.o
	rm zkp-rsa
