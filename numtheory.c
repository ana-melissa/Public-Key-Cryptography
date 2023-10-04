// numtheory.c
// Assignment 5: Public Key Cryptography

// Ana Melissa
// Prof. Long
// CSE 13S Fall 2021
// 11/8/2021

#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"

#include <stdbool.h>
#include <stdint.h>
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>

//	Citations:
//		Much of my code is based off of the pseudo code provided in the assignment 6 pdf.
//		I also attended Sloan's in person sections on Wednesdays (11/10/2021 & 11/17/2021) to get help with is_prime.
//		I attended Eric's section on wednesday (11/10/2021) and found his pseduo code for is_prime and make_prime helpful.
//      James Tennant helped me simplify my pow_mod implementation.

void gcd(mpz_t g, mpz_t a, mpz_t b) {
    //store a and b into temp so you can mess with it
    // create a variable t, create a temp variable for a and b
    mpz_t a_temp, b_temp, t;

    // initialize mpz_t variables
    mpz_inits(a_temp, b_temp, t, NULL);

    // set a to a_temp
    // set b to b_temp
    mpz_set(a_temp, a);
    mpz_set(b_temp, b);

    // compare b_temp and 0
    // return postive if b_temp > 0, zero if equal, negative b_temp < 0
    while (mpz_cmp_ui(b_temp, 0) != 0) {
        // set t as b
        mpz_set(t, b_temp);
        // set b to a mod b
        mpz_mod(b_temp, a_temp, b_temp);
        // set a to t
        mpz_set(a_temp, t);
    }

    // set empty g to a (this is similar to return statement)
    mpz_set(g, a_temp);
    mpz_clears(a_temp, b_temp, t, NULL);
    return;
}

void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {
    // create temp variables
    mpz_t sub_temp2, sub_temp, temp, temp2, t, t_prime, r, r_prime, q, r_temp, t_temp;

    // initialize mpz_t variables
    mpz_inits(sub_temp2, sub_temp, temp, temp2, t, t_prime, r, r_prime, q, r_temp, t_temp, NULL);

    // set r to n
    mpz_set(r, n);

    // set r_prime to a
    mpz_set(r_prime, a);

    // set t to 0
    mpz_set_si(t, 0);

    // set t_prime to 1
    mpz_set_si(t_prime, 1);

    // while r_prime is greater than zero
    while (mpz_cmp_ui(r_prime, 0) != 0) {

        mpz_fdiv_q(q, r, r_prime);

        mpz_set(r_temp, r);
        mpz_set(r, r_prime);
        mpz_mul(temp, q, r_prime);
        mpz_sub(sub_temp, r_temp, temp);
        mpz_set(r_prime, sub_temp);

        mpz_set(t_temp, t);
        mpz_set(t, t_prime);
        mpz_mul(temp2, q, t_prime);
        mpz_sub(sub_temp2, t_temp, temp2);
        mpz_set(t_prime, sub_temp2);
    }
    // if r is greater than 1
    if (mpz_cmp_si(r, 1) > 0) {
        // there is no inverse
        mpz_set_ui(i, 0);
        mpz_clears(
            sub_temp2, sub_temp, temp, temp2, t, t_prime, r, r_prime, q, r_temp, t_temp, NULL);
        return;
    }
    if (mpz_cmp_si(t, 0) < 0) {
        mpz_add(t, t, n);
    }

    mpz_set(i, t);

    // clear all variables
    mpz_clears(sub_temp2, sub_temp, temp, temp2, t, t_prime, r, r_prime, q, r_temp, t_temp, NULL);

    return;
}

void pow_mod(mpz_t out, mpz_t base, mpz_t exponent, mpz_t modulus) {
    // This function performs fast modular exponentation.
    // This function uses the binary squaring method.

    //computing base raised to the exponent power modulo.
    //modulus and storing the computed result in out.

    // James Tennant helped me simplify my pow_mod implementation.
    mpz_t p, d, n;

    mpz_init_set(p, base);
    mpz_init_set(d, exponent);
    mpz_init_set(n, modulus);
    mpz_set_ui(out, 1);

    while (mpz_sgn(d) == 1) {
        if (mpz_odd_p(d)) {
            mpz_mul(out, out, p);
            mpz_mod(out, out, n);
        }

        mpz_mul(p, p, p);
        mpz_mod(p, p, n);
        mpz_tdiv_q_2exp(d, d, 1);
    }
    mpz_clears(p, d, n, NULL);
    return;
}

bool is_prime(mpz_t n, uint64_t iters) {
    // Miller-Rabin primality test:
    // This function tests if n is prime using iters number of Miller-Rabin iterations.

    // check if n is 2 or 3, return true
    if (mpz_cmp_ui(n, 2) == 0 | mpz_cmp_ui(n, 3) == 0) {
        return true;
    }

    // check if n is 1, 0 or even becuase if it is this means that it cannot be a prime number.
    if (mpz_even_p(n) != 0 | mpz_cmp_ui(n, 1) == 0 | mpz_cmp_ui(n, 0) == 0) {
        return false;
    }

    //MILLER-RABIN(n, k)
    mpz_t r, a, y, lower, upper, n_1, mp2;

    mpz_inits(r, a, y, lower, upper, n_1, mp2, NULL);

    mpz_sub_ui(r, n, 1);
    mp_bitcnt_t s = 0;

    // create mpz value of 2
    mpz_set_ui(mp2, 2);

    //guess r
    while (mpz_even_p(r) != 0) {
        s = s + 1;
        mpz_fdiv_q_ui(r, r, 2);
    }

    // create n minus 1
    mpz_sub_ui(n_1, n, 1);

    // for i <- 1 to k
    for (uint64_t i = 0; i < iters; i += 1) {
        mpz_sub_ui(upper, n, 3);
        // choose random
        mpz_urandomm(a, state, upper);
        mpz_add_ui(a, a, 2);
        // call pwr mod
        pow_mod(y, a, r, n);

        // if y doesn't equal 1 and y doesn't equal n - 1
        if ((mpz_cmp_ui(y, 1) != 0) && mpz_cmp(y, n_1) != 0) {
            uint64_t j = 1;

            //while j <= s - 1 and y != n - 1
            while ((j <= (s - 1)) && (mpz_cmp(y, n_1) != 0)) {
                pow_mod(y, y, mp2, n);
                if (mpz_cmp_ui(y, 1) == 0) {
                    mpz_clears(r, a, y, lower, upper, n_1, mp2, NULL);
                    return false;
                }
                j = j + 1;
            }

            if (mpz_cmp(y, n_1) != 0) {
                mpz_clears(r, a, y, lower, upper, n_1, mp2, NULL);
                return false;
            }
        }
    }
    // clear all variables
    mpz_clears(r, a, y, lower, upper, n_1, mp2, NULL);

    return true;
}

void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    // this function generates a new prime number & stores in p.
    mpz_urandomb(p, state, bits);

    while (!is_prime(p, iters)) {
        mpz_urandomb(p, state, bits);
    }
    return;
}
