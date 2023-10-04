// decrypt.c
// Ana Melissa
// Prof. Long
// 11/21/2021
// CSE 13S Fall 2021

// This file contains the main() for the decryption program.
// This program needs the private key inorder to decrypt an encrypted file.

//	Citations:
// 		I attended Erics section on Wednesday 11/17/2021 and used pseudo code from that section.

#include "rsa.h"
#include "numtheory.h"

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

#define OPTIONS "i:o:n:vh"

int main(int argc, char **argv) {
    bool verbose = false;
    int opt = 0;
    FILE *infile = stdin;
    FILE *outfile = stdout;
    // set default public key file name
    char *privfile_name = "rsa.priv";

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
            privfile_name = optarg;
            break;

        case 'v':
            // enables verbose output
            verbose = true;
            break;

        case 'h':
            printf("SYNOPSIS\n");
            printf("   Decrypts data using RSA decryption.\n");
            printf("   Encrypted data is decrypted by the decrypt program.\n");
            printf("\n");
            printf("USAGE\n");
            printf("   ./decrypt [-hv] [-i infile] [-o outfile] -n pubkey -d privkey\n");
            printf("\n");
            printf("OPTIONS\n");
            printf("   -h               Display program help message and usage.\n");
            printf("   -v               Display verbose program output.\n");
            printf("   -i infile        Input file of data to decrypt (default: stdin).\n");
            printf("   -o outfile       Output file for decrypted data (default: stdout).\n");
            printf("   -n pvfile        Private key file (default rsa.priv).\n");
            break;

        default:
            printf("SYNOPSIS\n");
            printf("   Decrypts data using RSA decryption.\n");
            printf("   Encrypted data is decrypted by the decrypt program.\n");
            printf("\n");
            printf("USAGE\n");
            printf("   ./decrypt [-hv] [-i infile] [-o outfile] -n pubkey -d privkey\n");
            printf("\n");
            printf("OPTIONS\n");
            printf("   -h                Display program help message and usage.\n");
            printf("   -v                Display verbose program output.\n");
            printf("   -i infile         Input file of data to decrypt (default: stdin).\n");
            printf("   -o outfile        Output file for decrypted data (default: stdout).\n");
            printf("   -n pvfile         Private key file (default rsa.priv).\n");
            return 1;
        }
    }

    // open the private key file
    FILE *pvfile = fopen(privfile_name, "r");
    // in the event of failure
    if (pvfile == NULL) {
        // print error message
        printf("unable to open pvfile.\n");
        return 1;
    }

    // n is the modulus, e is the public key
    mpz_t n, e;
    mpz_inits(e, n, NULL);

    // Read the private key from pvfile
    rsa_read_priv(n, e, pvfile);

    if (verbose) {
        // (n) the public modulus n
        printf("n (%zu bits) = ", mpz_sizeinbase(n, 2));
        gmp_printf("%Zd\n", n);

        // (e) print the public exponent e
        printf("e (%zu bits) = ", mpz_sizeinbase(e, 2));
        gmp_printf("%Zd\n", e);
    }

    // read in the file
    rsa_decrypt_file(infile, outfile, n, e);

    // clear all you variables
    mpz_clears(n, e, NULL);

    // close all files
    fclose(infile);
    fclose(outfile);
    fclose(pvfile);

    return 0;
}
