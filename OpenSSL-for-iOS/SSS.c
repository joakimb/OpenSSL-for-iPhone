//
//  SSS.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-15.
//
#include "SSS.h"

void shamir_shares_generate(const EC_GROUP *group, EC_POINT *shares[], const EC_POINT *secret, const int t, const int n, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);

    // sample coefficients
    BIGNUM *coeffs[t+1]; // coefficient container (on stack)
    coeffs[0] = bn_new();
    BN_set_word(coeffs[0], 0);
    for (int i = 1; i < t + 1; i++){
        coeffs[i] = bn_random(order, ctx);
    }

    // make shares
    BIGNUM *peval = bn_new(); // space for evaluating polynomial
    BIGNUM *pterm = bn_new(); // space for storing polynomial terms
    BIGNUM *base = bn_new(); // space for storing polynomial terms
    BIGNUM *exp = bn_new(); // space for storing polynomial terms
    // make shares for user i, counting starts from 1, not 0
    for (int i=1; i<=n; i++){
        BN_set_word(peval, 0); // reset space for reuse

        // evaluate polynomial
        for (int j=0; j<t+1; j++) { // coeff * i ** j
            BN_set_word(base, i);
            BN_set_word(exp, j);
            BN_mod_exp(pterm, base, exp, order, ctx); // pterm = i^j mod order
            BN_mod_mul(pterm, coeffs[j], pterm, order, ctx); // pterm *= coeff
            BN_mod_add(peval, peval, pterm, order, ctx); // peval += pterm mod order
        }
        shares[i-1] = bn2point(group, peval, ctx); // allocate new share = generator ^ peval
        point_add(group, shares[i - 1], shares[i - 1], secret, ctx);
    }

    // cleanup
    for (int i=0; i<t+1; i++){
        bn_free(coeffs[i]);
    }
    bn_free(peval);
    bn_free(pterm);
    bn_free(base);
    bn_free(exp);
}

void lagX(const EC_GROUP *group, BIGNUM *prod, const int share_indexes[], int length, int i, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);

    BIGNUM *a = bn_new();
    BIGNUM *b = bn_new();
    BIGNUM *numerator = bn_new();
    BIGNUM *denominator = bn_new();
    BIGNUM *fraction = bn_new();
    BN_set_word(prod, 1);

    for (int j = 0; j < length; j++) {
        if (i == j) {
            continue;
        }
        BN_set_word(a, 0);
        BN_set_word(b, share_indexes[j]);
        BN_mod_sub(numerator, a, b, order, ctx);
        BN_set_word(a, share_indexes[i]);
        BN_set_word(b, share_indexes[j]);
        BN_mod_sub(denominator, a, b, order, ctx);
        BN_mod_inverse(denominator, denominator, order, ctx);
        BN_mod_mul(fraction, numerator, denominator, order, ctx);
        BN_mod_mul(prod, prod, fraction, order, ctx);
    }

    // cleanup
    bn_free(fraction);
    bn_free(denominator);
    bn_free(numerator);
    bn_free(b);
    bn_free(a);
}

EC_POINT *shamir_shares_reconstruct(const EC_GROUP *group, const EC_POINT *shares[], const int shareIndexes[], const int t, const int length, BN_CTX *ctx) {
    // TODO: remove parameter t input (unused)
    if (length != t+1) { // incorrect number of shares to reconstruct secret
        return NULL;
    }

    BIGNUM *zero = bn_new();
    BN_set_word(zero, 0); // explicitly set, probably superfluous
    EC_POINT *term = point_new(group);
    EC_POINT *sum = bn2point(group, zero, ctx);

    BIGNUM *lagrange_prod = bn_new();
    for (int i=0; i<length; i++) {
        lagX(group, lagrange_prod, shareIndexes, length, i, ctx);
        point_mul(group, term, lagrange_prod, shares[i], ctx);
        point_add(group, sum, sum, term, ctx);
    }

    // cleanup
    point_free(term);
    bn_free(lagrange_prod);
    bn_free(zero);
    return sum; // return secret
}

int shamir_shares_test_suite(int print) {

    print_allocation_status();

    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();

//    const int t = 1000; // t + 1 needed to reconstruct
//    const int n = 2000;
    const int t = 1; // t + 1 needed to reconstruct
    const int n = 3;
    EC_POINT *shares[n];

    BIGNUM *seven = bn_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = bn2point(group, seven, ctx);


    // generate shares
    shamir_shares_generate(group, shares, secret, t, n, ctx);


    // reconstruct with 2nd and 3rd share
    int share_indexes[t + 1];
    const EC_POINT *recShares[t + 1];
    for (int i=0; i<t+1; i++) {
        share_indexes[i] = i + 2; // user indices 1 to t + 1
        recShares[i] = shares[i + 1];
    }
    EC_POINT *reconstructed = shamir_shares_reconstruct(group, recShares, share_indexes, t, t+1, ctx);

    // check reconstruction
    int res = point_cmp(group, secret, reconstructed, ctx);

    // cleanup
    for (int i=0; i<n; i++) {
        point_free(shares[i]);
    }
    bn_free(seven);
    point_free(secret);
    point_free(reconstructed);
    BN_CTX_free(ctx);

#ifdef DEBUG
    print_allocation_status();
#endif
    return res;
}
