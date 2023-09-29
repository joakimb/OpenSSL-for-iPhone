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
    EC_POINT_free(pi->u);
    pi->u = NULL; // superflous safety
    BN_free(pi->z);
    pi->z = NULL; // superflous safety
}

void nizk_dl_prove(const EC_GROUP *group, const BIGNUM *x, nizk_dl_proof *pi, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);
    const EC_POINT *generator = get0_generator(group);

    // compute X
    EC_POINT *X = bn2point(group, x, ctx);

    // compute u
    BIGNUM *r = random_bignum(order, ctx);
    pi->u = bn2point(group, r, ctx);

    // compute c
    BIGNUM *c = openssl_hash_ppp2bn(group, generator, X, pi->u, ctx);

    // compute z
    pi->z = BN_new();
    int ret = BN_mod_mul(pi->z, c, x, order, ctx);
    assert(ret == 1 && "BN_mod_mul computation failed in nizk_dl_prove");
    ret = BN_mod_add(pi->z, pi->z, r, order, ctx);
    assert(ret == 1 && "BN_mod_add computation failed in nizk_dl_prove");

    // cleanup
    BN_free(c);
    BN_free(r);
    EC_POINT_free(X);
    /* implicitly return pi = (u, z) */
}

int nizk_dl_verify(const EC_GROUP *group, const EC_POINT *X, const nizk_dl_proof *pi, BN_CTX *ctx) {
    const EC_POINT *generator = get0_generator(group);

    // compute Z
    EC_POINT *Z = bn2point(group, pi->z, ctx);

    // compute Z_prime
    EC_POINT *Z_prime = EC_POINT_new(group);

    BIGNUM *c = openssl_hash_ppp2bn(group, generator, X, pi->u, ctx);
    EC_POINT_mul(group, Z_prime, NULL, X, c, ctx);
    EC_POINT_add(group, Z_prime, Z_prime, pi->u, ctx);
    
    // Z == Z_prime ?
    int ret = EC_POINT_cmp(group, Z, Z_prime, ctx);

    // cleanup
    BN_free(c);
    EC_POINT_free(Z_prime);
    EC_POINT_free(Z);

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
    BIGNUM *seven = BN_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = EC_POINT_new(group);
    EC_POINT_mul(group, secret, seven, NULL, NULL, ctx);
    if (print) {
        printf("secret: ");
        print_point(group, secret, ctx);
        printf("\n");
    }
    
    // test 1: produce correct proof and verify
    nizk_dl_proof pi;
    nizk_dl_prove(group, seven, &pi, ctx);
    int ret1 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        printf("Test 1 %s: Correct NIZK DL Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // cleanup
    nizk_dl_proof_free(&pi);
    EC_POINT_free(secret);
    BN_free(seven);
    BN_CTX_free(ctx);

    // return test results
    return ret1 != 0;
}

static int nizk_dl_test_2(int print) {
    const EC_GROUP *group = get0_group();
    const BIGNUM *order = get0_order(group);
    
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *seven = BN_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = EC_POINT_new(group);
    EC_POINT_mul(group, secret, seven, NULL, NULL, ctx);
    if (print) {
        printf("secret: ");
        print_point(group, secret, ctx);
        printf("\n");
    }

    // produce correct proof and verify
    nizk_dl_proof pi;
    nizk_dl_prove(group, seven, &pi, ctx);
    int ret1 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        printf("Test 2 part 1 %s: Correct NIZK DL Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // negative tests
    // try to verify incorrect proof (z-value wrong)
    BN_free(pi.z);
    pi.z = random_bignum(order, ctx); // omitted to check if new erroneous z-value is actually by chance the correct value
    int ret2 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        if (ret2) {
            printf("Test 2 part 2 OK: Incorrect NIZK DL Proof not accepted (which is CORRECT)\n");
        } else {
            printf("Test 2 part 2 NOT OK: Incorrect NIZK DL Proof IS accepted (which is an ERROR)\n");
        }
    }

    // cleanup
    nizk_dl_proof_free(&pi);
    EC_POINT_free(secret);
    BN_free(seven);
    BN_CTX_free(ctx);

    // return test results
    return !(ret1 == 0 && ret2 != 0);
}

static int nizk_dl_test_3(int print) {
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *seven = BN_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = EC_POINT_new(group);
    EC_POINT_mul(group, secret, seven, NULL, NULL, ctx);
    if (print) {
        printf("secret: ");
        print_point(group, secret, ctx);
        printf("\n");
    }

    // produce correct proof and verify
    nizk_dl_proof pi;
    nizk_dl_prove(group, seven, &pi, ctx);
    int ret1 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        printf("Test 3 part 1 %s: Correct NIZK DL Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // negative tests
    // try to verify incorrect proof (both u- and z-value wrong)
    EC_POINT_free(pi.u);
    pi.u = random_point(group, ctx);  // omitted to check if modified u-value actually by chance produces a valid proof
    int ret2 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        if (ret2) {
            printf("Test 3 part 2 OK: Incorrect NIZK DL Proof not accepted (which is CORRECT)\n");
        } else {
            printf("Test 3 part 2 NOT OK: Incorrect NIZK DL Proof IS accepted (which is an ERROR)\n");
        }
    }

    // cleanup
    nizk_dl_proof_free(&pi);
    EC_POINT_free(secret);
    BN_free(seven);
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
    int num_tests = sizeof(test_suite)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite[i](print)) {
            ret = 1;
        }
    }
    return ret;
}
