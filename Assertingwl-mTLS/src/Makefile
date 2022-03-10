# makefile for a proof of ownership of a RSA signature
# it considers that openssl is installed in the standard path

CC=gcc
RM=rm -f
AR=ar

CFLAGS+=-g -Wall -m64 -I. -L.
CFLAGS+=-lssl -lcrypto -lzkprsa

LIB=libzkprsa.a
TEST=test_zkprsa

DEPS=rsa_sig_proof.h rsa_evp_sig.h rsa_bn_sig.h rsa_sig_proof_util.h

all: lib test

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

lib: rsa_sig_proof.o rsa_sig_proof_util.o
	$(AR) rcs $(LIB) $^

test: main.o rsa_evp_sig.o rsa_bn_sig.o
	$(CC) -o $(TEST) $^ $(CFLAGS)

.PHONY: clean
clean:
	$(RM) *.o
	$(RM) $(TEST)
	$(RM) $(LIB)
