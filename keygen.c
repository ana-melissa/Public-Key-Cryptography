// keygen.c
// Assignment 6

// Ana Melissa
// Prof. Long
// 11/15/2021
// CSE 13S Fall 2021

// This file implements the generation of private and public keys.

// Citations:
//		I attended Erics section on 11/17/2021 and used Eric's pseudo code from that section.

#include "randstate.h"
#include "numtheory.h"
#include "rsa.h"

#include <unistd.h>
#include <inttypes.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>
#include <fcntl.h>
#include <time.h>

#define OPTIONS "b:i:n:d:s:vh"

gmp_randstate_t state;

int main(int argc, char **argv) {
    int opt = 0;

    // set default values for command line options
    char *pbname = "rsa.pub";
    char *pvname = "rsa.priv";
    uint32_t n_bits = 256;
    uint32_t iterations = 50;
    // default seed: the seconds since the UNIX epoch, given by time(NULL)
    uint32_t seed = time(NULL);

    bool verbose = false;

    // Get current user's name as a string using getenv()
    char *username = getenv("USER");

    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {

        case 'b':
            // specifies the minimum bits needed for the public mod n (default: 256)
            n_bits = atoi(optarg);
            break;

        case 'i':
            //specifies the number of Miller-Rabin iterations for testing primes (default: 50)
            iterations = atoi(optarg);
            break;

        case 'n':
            // specifies the public key file (default rsa.pub)
            pbname = optarg;
            break;

        case 'd':
            // specifies the private key file (default rsa.priv)
            pvname = optarg;
            break;

        case 's':
            // specifies the random seed for the random state initialization (default: time)
            seed = atoi(optarg);
            break;

        case 'v':
            // enables verbose
            verbose = true;
            break;

        case 'h':
            // display help message
            printf("SYNOPSIS\n");
            printf("   Generates an RSA public/private key pair.\n");
            printf("\n");
            printf("USAGE\n");
            printf("   ./keygen [-hv] [-b bits] -n pbfile -d pvfile\n");
            printf("\n");
            printf("OPTIONS\n");
            printf("   -h             Display program help message and usage.\n");
            printf("   -v             Display verbose program output.\n");
            printf("   -b bits        Minimum bits needed for public key n.\n");
            printf("   -c confidence  Miller-Rabin iterations for testing primes (default: 50).\n");
            printf("   -n pbfile      Public key file (default rsa.pub).\n");
            printf("   -d pvfile      Private key file (default rsa.priv).\n");
            printf("   -s seed        Display program help message and usage.\n");
            break;

        default:
            // default help message and return 1 (false)
            printf("SYNOPSIS\n");
            printf("   Generates an RSA public/private key pair.\n");
            printf("\n");
            printf("USAGE\n");
            printf("   ./keygen [-hv] [-b bits] -n pbfile -d pvfile\n");
            printf("\n");
            printf("OPTIONS\n");
            printf("   -h             Display program help message and usage.\n");
            printf("   -v             Display verbose program output.\n");
            printf("   -b bits        Minimum bits needed for public key n.\n");
            printf("   -c confidence  Miller-Rabin iterations for testing primes (default: 50).\n");
            printf("   -n pbfile      Public key file (default rsa.pub).\n");
            printf("   -d pvfile      Private key file (default rsa.priv).\n");
            printf("   -s seed        Display program help message and usage.\n");
            return 1;
        }
    }

    // open public file with fopen()
    FILE *pbfile = fopen(pbname, "w");

    // in the event of failure
    if (pbfile == NULL) {
        // print a help error
        printf("no public file to open.\n");
        // exit program
        return 1;
    }

    // open private file with fopen()
    FILE *pvfile = fopen(pvname, "w");

    // in the event of failure
    if (pvfile == NULL) {
        // print a help error
        printf("no private file to open.\n");
        // exit program
        return 1;
    }

    // fchmod() and fileno() to make sure the private key file permisions are set
    // 0600 allow the user read and write permissions
    fchmod(fileno(pvfile), 0600);

    // Initialize the random state using randstate_init()
    randstate_init(seed);

    mpz_t s, p, q, n, e, d;
    mpz_inits(s, p, q, n, e, d, NULL);

    // Make the public and private keys using rsa_make_pub() and rsa_make_priv()
    rsa_make_pub(p, q, n, e, n_bits, iterations);
    rsa_make_priv(d, e, p, q);

    // convert username into an mpz_t with mpz_set_str() (base 62)
    mpz_set_str(s, username, 62);

    // use rsa_sign() to compute the signature of the username
    rsa_sign(s, s, d, n);

    // write the computed public / private key to their files
    rsa_write_pub(n, e, s, username, pbfile);
    rsa_write_priv(n, d, pvfile);

    // if verbose is true
    // all mpz_t values should be printed with info about the numboer of bits that constitute them and their respective values in decimal
    if (verbose) {
        // username
        printf("user: %s\n", username);

        // (s) print signature s
        printf("s (%zu bits) = ", mpz_sizeinbase(s, 2));
        gmp_printf("%Zd\n", s);

        // (p) print the first large prime p
        printf("p (%zu bits) = ", mpz_sizeinbase(p, 2));
        gmp_printf("%Zd\n", p);

        // (q) print the second large prime q
        printf("q (%zu bits) = ", mpz_sizeinbase(q, 2));
        gmp_printf("%Zd\n", q);

        // (n) print the public modulus
        printf("n (%zu bits) = ", mpz_sizeinbase(n, 2));
        gmp_printf("%Zd\n", n);

        // (e) print the public exponent e
        printf("e (%zu bits) = ", mpz_sizeinbase(e, 2));
        gmp_printf("%Zd\n", e);

        // (d) print the private key d
        printf("d (%zu bits) = ", mpz_sizeinbase(d, 2));
        gmp_printf("%Zd\n", d);
    }

    //clear mpzs, close files, clear randstate
    fclose(pbfile);
    fclose(pvfile);
    randstate_clear();
    mpz_clears(s, p, q, n, e, d, NULL);
    return 0;
}
