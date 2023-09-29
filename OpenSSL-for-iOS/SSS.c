//
//  SSS.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-15.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//
#include <stdio.h>
#include "SSS.h"

void shamir_shares_generate(const EC_GROUP *group, EC_POINT *shares[], EC_POINT *secret, const int t, const int n, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);

    // sample coefficients
    BIGNUM *coeffs[t+1];
    coeffs[0] = BN_new();
    BN_set_word(coeffs[0], 0);
    for (int i = 1; i < t + 1; i++){
        coeffs[i] = random_bignum(order, ctx);
    }

    // make shares
    BIGNUM *peval = BN_new(); // space for evaluating polynomial
    BIGNUM *pterm = BN_new(); // space for storing polynomial terms
    BIGNUM *base = BN_new(); // space for storing polynomial terms
    BIGNUM *exp = BN_new(); // space for storing polynomial terms
    // make shares for user i, counting starts from 1, not 0
    for (int i = 1; i <= n; i++){
        BN_set_word(peval, 0); // reset space for reuse

        // evaluate polynomial
        for (int j = 0; j < t + 1; j++) { // coeff * i ** j
            BN_set_word(base, i);
            BN_set_word(exp, j);
            BN_mod_exp(pterm, base, exp, order, ctx); // pterm = i^j mod order
            BN_mod_mul(pterm, coeffs[j], pterm, order, ctx); // pterm *= coeff
            BN_mod_add(peval, peval, pterm, order, ctx); // peval += pterm mod order
        }
        shares[i - 1] = bn2point(group, peval, ctx); // share = generator ^ peval
        EC_POINT_add(group, shares[i - 1], shares[i - 1], secret, ctx); // share += secret
    }

    // cleanup
    for (int i = 0; i < t+1; i++){
        BN_free(coeffs[i]);
    }
    BN_free(peval);
    BN_free(pterm);
    BN_free(base);
    BN_free(exp);
}

static void lagX(const EC_GROUP *group, BIGNUM *prod, int shareIndexes[], int length, int i, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);

    BIGNUM *numerator = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *denominator = BN_new();
    BIGNUM *fraction = BN_new();
    BN_set_word(prod, 1);

    for (int j = 0; j < length; j++) {
        if (i == j) {
            continue;
        }
        BN_set_word(a, 0);
        BN_set_word(b, shareIndexes[j]);
        BN_mod_sub(numerator, a, b, order, ctx);
        BN_set_word(a, shareIndexes[i]);
        BN_set_word(b, shareIndexes[j]);
        BN_mod_sub(denominator, a, b, order, ctx);
        BN_mod_inverse(denominator, denominator, order, ctx);
        BN_mod_mul(fraction, numerator, denominator, order, ctx);
        BN_mod_mul(prod, prod, fraction, order, ctx);
    }

    // cleanup
    BN_free(fraction);
    BN_free(denominator);
    BN_free(b);
    BN_free(a);
    BN_free(numerator);
}

EC_POINT *shamir_shares_reconstruct(const EC_GROUP *group, EC_POINT *shares[], int shareIndexes[], int t, int length, BN_CTX *ctx) {
    if (length != t+1) { // incorrect number of shares to reconstruct secret
        return NULL;
    }

    BIGNUM *zero = BN_new();
    BN_set_word(zero, 0); // probably superfluous
    EC_POINT *term = EC_POINT_new(group);
    EC_POINT *sum = bn2point(group, zero, ctx);

    BIGNUM *lagrangeProd = BN_new();
    for (int i=0; i<length; i++) {
        lagX(group, lagrangeProd, shareIndexes, length, i, ctx);
        EC_POINT_mul(group, term, NULL, shares[i], lagrangeProd, ctx);
        EC_POINT_add(group, sum, sum, term, ctx);
    }

    // cleanup
    EC_POINT_free(term);
    BN_free(lagrangeProd);
    BN_free(zero);
    return sum; // return secret
}

int shamir_shares_test_suite(int print) {
    const EC_GROUP *group = get0_group();
    const EC_POINT *generator = get0_generator(group);
    BN_CTX *ctx = BN_CTX_new();

//    const int t = 1000; // t + 1 needed to reconstruct
//    const int n = 2000;
    const int t = 1; // t + 1 needed to reconstruct
    const int n = 3;
    EC_POINT *shares[n];

    BIGNUM *seven = BN_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = EC_POINT_new(group);
    EC_POINT_mul(group, secret, NULL, generator, seven, ctx);
    if (print) {
        printf("secret: ");
        print_point(group, secret, ctx);
        printf("\n");
    }

    // generate shares
    shamir_shares_generate(group, shares, secret, t, n, ctx);

    if (print) {
        printf("shares:\n");
        for (int i=0; i<n; i++){
            print_point(group, shares[i], ctx);
            printf("\n");
        }
    }

    // reconstruct with 2nd and 3rd share
    int shareIndexes[t + 1];
    EC_POINT *recShares[t + 1];
    for (int i=0; i<t+1; i++) {
        shareIndexes[i] = i + 2; // user indices 1 to t + 1
        recShares[i] = shares[i + 1];
    }
    EC_POINT *reconstructed = shamir_shares_reconstruct(group, recShares, shareIndexes, t, t+1, ctx);

    // check reconstruction
    int res = EC_POINT_cmp(group, secret, reconstructed, ctx);
    if (print) {
        printf("reconstructed: ");
        print_point(group, reconstructed, ctx);
        printf("\nReconstruction %s\n", res ? "NOT OK" : "OK");
    }
    fflush(stdout);

    // cleanup
    BN_free(seven);
    EC_POINT_free(secret);
    EC_POINT_free(reconstructed);
    BN_CTX_free(ctx);
    
    return res;
}
