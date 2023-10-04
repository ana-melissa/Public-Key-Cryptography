// rsa.c
//Assignment 6

// Ana Melissa
// Prof. Long
// 11/15/2021
// CSE 13S Fall 2021

#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

//	Citations:
//	I used Eric's pseudo code for this file, specifically in:
//		rsa_make_pub
//		rsa_make_priv
//		rsa_encrypt_file
//		rsa_decrypt_file

// I also attended Eugenes section both weeks (tuesdays and thursdays), and used his pseudo code as guidance.

void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {

    // initially, p, q, n, and e are empty. This function fills them up.
    // create parts of new RSA public key: two large primes p and q, prduct n and public exponent e

    // create variables for the computed gcd, (p - 1), and (q - 1)
    mpz_t totient, computed_gcd, p_min, q_min;
    mpz_inits(totient, computed_gcd, p_min, q_min, NULL);

    // let the number of bits for p be a random number in the range [nbits/4, (3 x nbits) / 4]
    uint64_t p_bits = (1 + random() % (nbits / 2) + (nbits / 4));
    // remaining bits go to q
    uint64_t q_bits = nbits - p_bits;

    // decide the number of bits that can go to primes such that log 2 (n) >= nbits
    //while (log 2 is not greater than or equal to nbits)
    while (!(mpz_sizeinbase(n, 2) >= nbits)) {

        // call make primt to create primes p and q
        make_prime(p, p_bits, iters);
        make_prime(q, q_bits, iters);

        mpz_mul(n, p, q);

        // compute totient(n) = (p - 1)(q - 1)
        mpz_sub_ui(p_min, p, 1);
        mpz_sub_ui(q_min, q, 1);
        mpz_mul(totient, p_min, q_min);

        // find expenent e with a do while loop to generate random numbers of nbits using mpz_urandomb()
        do {
            mpz_urandomb(e, state, nbits);
            // compute the gcd() of e and  totient
            gcd(computed_gcd, e, totient);

            // stop the loop when there is a number that is coprime with the totient
        } while (mpz_cmp_ui(computed_gcd, 1) != 0);
    }
    mpz_clears(totient, computed_gcd, p_min, q_min, NULL);

    return;
}

void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    // write public key to pbfile
    gmp_fprintf(pbfile, "%Zx\n", n);
    gmp_fprintf(pbfile, "%Zx\n", e);
    gmp_fprintf(pbfile, "%Zx\n", s);
    fprintf(pbfile, "%s\n", username);
    return;
}

void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {

    // reads the public rsa key from pbfile.
    gmp_fscanf(pbfile, "%Zx\n", n);
    gmp_fscanf(pbfile, "%Zx\n", e);
    gmp_fscanf(pbfile, "%Zx\n", s);
    fscanf(pbfile, "%s\n", username);
    return;
}

void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
    // creates a new RSA private key d given primes p and q and public exponent e
    // to compute d, compute the inverse of e modulo p(n) = (p - 1)(q - 1)

    // inititalize totient, p_min_1, q_min_1
    mpz_t totient, p_1, q_1;
    mpz_inits(totient, p_1, q_1, NULL);

    mpz_sub_ui(p_1, p, 1);
    mpz_sub_ui(q_1, q, 1);

    mpz_mul(totient, p_1, q_1);
    mod_inverse(d, e, totient);
    mpz_clears(totient, p_1, q_1, NULL);

    return;
}

void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    // write private key to private file
    gmp_fprintf(pvfile, "%Zx\n", n);
    gmp_fprintf(pvfile, "%Zx\n", d);
    return;
}

void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    // read private key into program
    gmp_fscanf(pvfile, "%Zx\n", n);
    gmp_fscanf(pvfile, "%Zx\n", d);
    return;
}

void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    // take message (raise power e and mod by n) -> this is RSA Encryption
    pow_mod(c, m, e, n);
    return;
}

void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) { // {
    // encrypted in blocks and not entire file becuase of n (modulo n)
    // value of block cannot be 0 or 1 -> prepend byte 0xFF

    // initialize variables
    mpz_t c, m;
    mpz_inits(c, m, NULL);
    size_t j;

    // calculate the block size k
    size_t k = (mpz_sizeinbase(n, 2) - 1) / 8;

    // create space for array
    uint8_t *block_array = calloc(k, sizeof(uint8_t));

    // set the first index of the array to 0xFF
    block_array[0] = 0xFF;

    // while you have not reached the end of the file:
    while (feof(infile) == 0) {
        // bytes read
        j = fread(block_array + 1, sizeof(uint8_t), k - 1, infile);
        if (j > 0) {
            // convert the read bytes and set to m
            mpz_import(m, j + 1, 1, sizeof(uint8_t), 1, 0, block_array);
            // encrypt m
            rsa_encrypt(c, m, e, n);
            gmp_fprintf(outfile, "%Zx\n", c);
        }
    }

    mpz_clears(c, m, NULL);
    free(block_array);
    return;
}

void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    // D(c) = m = c^d(mod n)
    pow_mod(m, c, d, n);
    return;
}

void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {

    mpz_t c, m;

    mpz_inits(c, m, NULL);

    size_t j; // number of bytes converted

    // calcuate the size of k using log
    size_t k = (mpz_sizeinbase(n, 2) - 1 / 8);

    // allocate space for block array
    uint8_t *block_array = calloc(k, sizeof(uint8_t));

    // while you have not reached the end of the file:
    while (feof(infile) == 0) {
        // while there is cipher text to read
        if (gmp_fscanf(infile, "%Zx\n", c) > 0) {
            // decrypt encrypted text
            rsa_decrypt(m, c, d, n);

            // convert c back into bytes and store them in block array
            mpz_export(block_array, &j, 1, sizeof(uint8_t), 1, 0, m);

            // write out j - 1 because of 0xFF
            fwrite(block_array + 1, sizeof(uint8_t), j - 1, outfile);
        }
    }
    // clear variables and free
    mpz_clears(c, m, NULL);
    free(block_array);
    return;
}

void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    // create signature.
    // store value in s (s initially empty)
    pow_mod(s, m, d, n);
    return;
}

bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    // This function verifys a user's username.
    // m is message
    mpz_t t;
    mpz_init(t);

    pow_mod(t, s, e, n);

    if (mpz_cmp(m, t) == 0) {
        mpz_clear(t);
        return true;
    } else {
        mpz_clear(t);
        return false;
    }
}
