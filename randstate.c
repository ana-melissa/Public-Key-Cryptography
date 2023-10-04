// randstate.c
//Assignment 5: Public Key Cryptography

// Ana Melissa
// Prof. Long
// CSE 13S Fall 2021
// 11/8/2021

// GMP (multiple precision arithmetic library) requires us
// to explicitly initialize a random state variable and pass
// it to any of the random integer functions in GMP

// randstate.h -> randstate.c
// implements a small state module
// cleans up any memory used by the initialized random state

// single extern declaration to global random state variable 'state'

#include "randstate.h"
#include <gmp.h>
#include <stdio.h>
#include <stdint.h>

gmp_randstate_t state;

// initialize the state
void randstate_init(uint64_t seed) {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
    return;
}

// clear the state
void randstate_clear(void) {
    // frees any memory associated with the random state
    gmp_randclear(state);
    return;
}
