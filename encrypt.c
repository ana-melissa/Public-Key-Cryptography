// encrypt.c
// Assignment 6

// Ana Melissa
// Prof. Long
// CSE 13S Fall 2021
// 11/21/2021

// This file contains the main() to encrypt any given file.
// To encrypt a file, this program needs a public key.

#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"

#include <unistd.h>
#include <inttypes.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmp.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>
#include <limits.h>

#define OPTIONS "i:o:n:vh"

int main(int argc, char **argv) {
    int opt = 0;
    FILE *infile = stdin;
    FILE *outfile = stdout;
    // set default public key file name
    char *pubfile_name = "rsa.pub";
    bool verbose = false;

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'i':
            //specifies the input file to encrypt (default: stdin)
            infile = fopen(optarg, "r");
            break;

        case 'o':
            // specifies the output file to encrypt (default stdout)
            outfile = fopen(optarg, "w");
            break;

        case 'n':
            //specifies the file containing the public key (default rsa.pub)
            pubfile_name = optarg;
            break;

        case 'v':
            // enables verbose output
            verbose = true;
            break;

        case 'h':
            printf("SYNOPSIS\n");
            printf("   Encrypts data using RSA encryption.\n");
            printf("   Encrypted data is decrypted by the decrypt program.\n");
            printf("\n");
            printf("USAGE\n");
            printf("   ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey -d privkey\n");
            printf("\n");
            printf("OPTIONS\n");
            printf("   -h               Display program help message and usage.\n");
            printf("   -v               Display verbose program output.\n");
            printf("   -i infile        Input file of data to encrypt (default: stdin).\n");
            printf("   -o outfile       Output file for encrypted data (default: stdout).\n");
            printf("   -n pbfile        Public key file (default rsa.pub).\n");
            break;

        default:

            printf("SYNOPSIS\n");
            printf("   Encrypts data using RSA encryption.\n");
            printf("   Encrypted data is decrypted by the decrypt program.\n");
            printf("\n");
            printf("USAGE\n");
            printf("   ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey -d privkey\n");
            printf("\n");
            printf("OPTIONS\n");
            printf("   -h                Display program help message and usage.\n");
            printf("   -v                Display verbose program output.\n");
            printf("   -i infile         Input file of data to encrypt (default: stdin).\n");
            printf("   -o outfile        Output file for encrypted data (default: stdout).\n");
            printf("   -n pbfile         Public key file (default rsa.pub).\n");
            return 1;
        }
    }

    // get the public key file using fopen()
    FILE *pbfile = fopen(pubfile_name, "r");
    // in the event of failure
    if (pbfile == NULL) {
        // print a helpful error
        printf("unable to open pbfile.\n");
    }

    // initialize a variable that can hold up to 9 to hold your username in
    char username[_POSIX_LOGIN_NAME_MAX];

    // create variables to use in read public
    mpz_t m, s, n, e;
    mpz_inits(m, s, n, e, NULL);

    // read the public key from the opened public key file
    rsa_read_pub(n, e, s, username, pbfile);

    // print verbose statements
    if (verbose) {
        // username
        printf("user = %s\n", username);

        // (s) print signature s
        printf("s (%zu bits) = ", mpz_sizeinbase(s, 2));
        gmp_printf("%Zd\n", s);

        // (n) the public modulus n
        printf("n (%zu bits) = ", mpz_sizeinbase(n, 2));
        gmp_printf("%Zd\n", n);

        // (e) print the public exponent e
        printf("e (%zu bits) = ", mpz_sizeinbase(e, 2));
        gmp_printf("%Zd\n", e);
    }

    // convert username into an mpz_t with mpz_set_str() (base 62)
    mpz_set_str(m, username, 62);

    // verify the signature using rsa_verify
    if (!rsa_verify(m, s, e, n)) {

        printf("Message not verified.\n");
        return -1;
    }

    // encrypt the file
    rsa_encrypt_file(infile, outfile, n, e);

    // close all files for no memory leaks
    fclose(infile);
    fclose(outfile);
    fclose(pbfile);

    // clear mpz values
    mpz_clears(m, s, n, e, NULL);
    return 0;
}
