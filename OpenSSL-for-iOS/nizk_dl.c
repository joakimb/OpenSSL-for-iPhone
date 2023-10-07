//
//  nizk_dl.c
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-09-29.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#include <stdio.h>
#include <assert.h>
#include "nizk_dl.h"
#include "openssl_hashing_tools.h"

void nizk_dl_proof_free(nizk_dl_proof *pi) {
    assert(pi && "nizk_dl_proof_free: usage error, no proof passed");
    assert(pi->u && "nizk_dl_proof_free: usage error, u is NULL");
    assert(pi->z && "nizk_dl_proof_free: usage error, z is NULL");
    point_free(pi->u);
    pi->u = NULL; // superflous safety
    bn_free(pi->z);
    pi->z = NULL; // superflous safety
}

void nizk_dl_prove(const EC_GROUP *group, const BIGNUM *x, nizk_dl_proof *pi, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);
    const EC_POINT *generator = get0_generator(group);

    // compute X
    EC_POINT *X = bn2point(group, x, ctx);

    // compute u
    BIGNUM *r = bn_random(order, ctx);
    pi->u = bn2point(group, r, ctx);

    // compute c
    BIGNUM *c = openssl_hash_points2bn(group, ctx, 3, generator, X, pi->u);

    // compute z
    pi->z = bn_new();
    int ret = BN_mod_mul(pi->z, c, x, order, ctx);
    assert(ret == 1 && "BN_mod_mul computation failed in nizk_dl_prove");
    ret = BN_mod_add(pi->z, pi->z, r, order, ctx);
    assert(ret == 1 && "BN_mod_add computation failed in nizk_dl_prove");

    // cleanup
    bn_free(c);
    bn_free(r);
    point_free(X);
    /* implicitly return pi = (u, z) */
}

int nizk_dl_verify(const EC_GROUP *group, const EC_POINT *X, const nizk_dl_proof *pi, BN_CTX *ctx) {
    const EC_POINT *generator = get0_generator(group);

    // compute Z
    EC_POINT *Z = bn2point(group, pi->z, ctx);

    // compute Z_prime
    EC_POINT *Z_prime = point_new(group);

    BIGNUM *c = openssl_hash_points2bn(group, ctx, 3, generator, X, pi->u);
    point_mul(group, Z_prime, c, X, ctx);
    point_add(group, Z_prime, Z_prime, pi->u, ctx);

    // Z == Z_prime? (zero if equal)
    int ret = point_cmp(group, Z, Z_prime, ctx);

    // cleanup
    bn_free(c);
    point_free(Z_prime);
    point_free(Z);

    return ret;
}

/*
 *
 *  nizk_dl tests
 *
 */

static int nizk_dl_test_1(int print) {
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *seven = bn_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = bn2point(group, seven, ctx);
    
    // test 1: produce correct proof and verify
    nizk_dl_proof pi;
    nizk_dl_prove(group, seven, &pi, ctx);
    int ret = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        printf("%6s Test 1: Correct NIZK DL Proof %s accepted\n", ret ? "NOT OK" : "OK", ret ? "NOT" : "indeed");
    }

    // cleanup
    nizk_dl_proof_free(&pi);
    point_free(secret);
    bn_free(seven);
    BN_CTX_free(ctx);

    // return test results
    return ret != 0;
}

static int nizk_dl_test_2(int print) {
    const EC_GROUP *group = get0_group();
    const BIGNUM *order = get0_order(group);
    
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *seven = bn_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = bn2point(group, seven, ctx);

    // produce correct proof and verify
    nizk_dl_proof pi;
    nizk_dl_prove(group, seven, &pi, ctx);
    int ret1 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        printf("%6s Test 2 - 1: Correct NIZK DL Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // negative tests
    // try to verify incorrect proof (z-value wrong)
    bn_free(pi.z);
    pi.z = bn_random(order, ctx); // omitted to check if new erroneous z-value is actually by chance the correct value
    int ret2 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        if (ret2) {
            printf("    OK Test 2 - 2: Incorrect NIZK DL Proof not accepted (which is CORRECT)\n");
        } else {
            printf("NOT OK Test 2 - 2: Incorrect NIZK DL Proof IS accepted (which is an ERROR)\n");
        }
    }

    // cleanup
    nizk_dl_proof_free(&pi);
    point_free(secret);
    bn_free(seven);
    BN_CTX_free(ctx);

    // return test results
    return !(ret1 == 0 && ret2 != 0);
}

static int nizk_dl_test_3(int print) {
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *seven = bn_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = bn2point(group, seven, ctx);

    // produce correct proof and verify
    nizk_dl_proof pi;
    nizk_dl_prove(group, seven, &pi, ctx);
    int ret1 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        printf("%6s Test 3 - 1: Correct NIZK DL Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // negative tests
    // try to verify incorrect proof (both u- and z-value wrong)
    point_free(pi.u);
    pi.u = point_random(group, ctx);  // omitted to check if modified u-value actually by chance produces a valid proof
    int ret2 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        if (ret2) {
            printf("    OK Test 3 - 2: Incorrect NIZK DL Proof not accepted (which is CORRECT)\n");
        } else {
            printf("NOT OK Test 3 - 2: Incorrect NIZK DL Proof IS accepted (which is an ERROR)\n");
        }
    }

    // cleanup
    nizk_dl_proof_free(&pi);
    point_free(secret);
    bn_free(seven);
    BN_CTX_free(ctx);

    // return test results
    return !(ret1 == 0 && ret2 != 0);
}

typedef int (*test_function)(int);

static test_function test_suite[] = {
    &nizk_dl_test_1,
    &nizk_dl_test_2,
    &nizk_dl_test_3
};

// return test results
//   0 = passed (all individual tests passed)
//   1 = failed (one or more individual tests failed)
// setting print to 0 (zero) suppresses stdio printouts, while print 1 is 'verbose'
int nizk_dl_test_suite(int print) {
    if (print) {
        printf("NIZK DL test suite\n");
    }
    int num_tests = sizeof(test_suite)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite[i](print)) {
            ret = 1;
        }
    }
    if (print) {
        fflush(stdout);
    }
    return ret;
}
