//
//  nizk_reshare.c
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-09-29.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//
#include <stdio.h>
#include <assert.h>
#include "nizk_reshare.h"
#include "openssl_hashing_tools.h"

void nizk_reshare_proof_free(nizk_reshare_proof *pi) {
    assert(pi && "nizk_reshare_proof_free: usage error, no proof passed");
    assert(pi->R1 && "nizk_reshare_proof_free: usage error, R1 is NULL");
    assert(pi->R2 && "nizk_reshare_proof_free: usage error, R2 is NULL");
    assert(pi->R3 && "nizk_reshare_proof_free: usage error, R3 is NULL");
    assert(pi->z1 && "nizk_reshare_proof_free: usage error, z1 is NULL");
    assert(pi->z2 && "nizk_reshare_proof_free: usage error, z2 is NULL");
    EC_POINT_free(pi->R1);
    pi->R1 = NULL; // superflous safety
    EC_POINT_free(pi->R2);
    pi->R2 = NULL; // superflous safety
    EC_POINT_free(pi->R3);
    pi->R3 = NULL; // superflous safety
    BN_free(pi->z1);
    pi->z1 = NULL; // superflous safety
    BN_free(pi->z2);
    pi->z2 = NULL; // superflous safety
}

void nizk_reshare_prove(const EC_GROUP *group, const BIGNUM *w1, const BIGNUM *w2, const EC_POINT *ga, const EC_POINT *gb, const EC_POINT *gc, const EC_POINT *Y1, const EC_POINT *Y2, const EC_POINT *Y3, nizk_reshare_proof *pi, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);

    BIGNUM *r1 = random_bignum(order, ctx);
    BIGNUM *r2 = random_bignum(order, ctx);
    pi->R1 = EC_POINT_new(group);
    point_mul(group, pi->R1, r1, ga, ctx);
    pi->R2 = EC_POINT_new(group);
    point_mul(group, pi->R2, r2, ga, ctx);
    EC_POINT *gb_r2 = EC_POINT_new(group);
    point_mul(group, gb_r2, r2, gb, ctx);
    EC_POINT *gc_r1 = EC_POINT_new(group);
    point_mul(group, gc_r1, r1, gc, ctx);
    pi->R3 = EC_POINT_new(group);
    point_sub(group, pi->R3, gb_r2, gc_r1, ctx);

    BIGNUM *c = openssl_hash_ppppppppp2bn(group, ga, gb, gc, Y1, Y2, Y3, pi->R1, pi->R2, pi->R3, ctx);

    pi->z1 = BN_new();
    BN_mod_mul(pi->z1, c, w1, order, ctx);
    BN_mod_add(pi->z1, pi->z1, r1, order, ctx); // r1 + c * w1

    pi->z2 = BN_new();
    BN_mod_mul(pi->z2, c, w2, order, ctx);
    BN_mod_add(pi->z2, pi->z2, r2, order, ctx); // r2 + c * w2
    // implicitly return proof pi
    
    BN_free(c);
    EC_POINT_free(gb_r2);
    EC_POINT_free(gc_r1);
}

int nizk_reshare_verify(const EC_GROUP *group, const EC_POINT *ga, const EC_POINT *gb, const EC_POINT *gc, const EC_POINT *Y1, const EC_POINT *Y2, const EC_POINT *Y3, const nizk_reshare_proof *pi, BN_CTX *ctx) {
    
    BIGNUM *c = openssl_hash_ppppppppp2bn(group, ga, gb, gc, Y1, Y2, Y3, pi->R1, pi->R2, pi->R3, ctx);
    
   /* check discrete logarithm of Y1 part of proof*/
    EC_POINT *R1cY1 = EC_POINT_new(group);
    point_mul(group, R1cY1, c, Y1, ctx);
    EC_POINT_add(group, R1cY1, pi->R1, R1cY1, ctx);
    EC_POINT *z1ga = EC_POINT_new(group);
    point_mul(group, z1ga, pi->z1, ga, ctx);
    int ret = EC_POINT_cmp(group, R1cY1, z1ga, ctx);
    assert(ret != -1 && "nizk_reshare_verify_Y1: error in EC_POINT_cmp()");
    EC_POINT_free(z1ga);
    EC_POINT_free(R1cY1);
    if (ret == 1) { //not equal
        BN_free(c);
        return 1; // verification failed
    }
    
    /* check discrete logarithm of Y2 part of proof*/
    EC_POINT *R2cY2 = EC_POINT_new(group);
    point_mul(group, R2cY2, c, Y2, ctx);
    EC_POINT_add(group, R2cY2, pi->R2, R2cY2, ctx);
    EC_POINT *z2ga = EC_POINT_new(group);
    point_mul(group, z2ga, pi->z2, ga, ctx);
    ret = EC_POINT_cmp(group, R2cY2, z2ga, ctx);
    assert(ret != -1 && "nizk_reshare_verify_Y2: error in EC_POINT_cmp()");
    EC_POINT_free(z2ga);
    EC_POINT_free(R2cY2);
    if (ret == 1) { //not equal
        BN_free(c);
        return 1; // verification failed
    }
    
    /* check pedersen commitment for Y3 part of proof*/
    EC_POINT *R3cY3 = EC_POINT_new(group);
    point_mul(group, R3cY3, c, Y3, ctx);
    EC_POINT_add(group, R3cY3, pi->R3, R3cY3, ctx);
    EC_POINT *z2gb = EC_POINT_new(group);
    point_mul(group, z2gb, pi->z2, gb, ctx);
    EC_POINT *z1gc = EC_POINT_new(group);
    point_mul(group, z1gc, pi->z1, gc, ctx);
    EC_POINT *z2gb_z2gc = z1gc;
    point_sub(group, z2gb_z2gc, z2gb, z1gc, ctx);
    ret = EC_POINT_cmp(group, R3cY3, z2gb_z2gc, ctx);
    assert(ret != -1 && "nizk_reshare_verify_Y3: error in EC_POINT_cmp()");
    EC_POINT_free(R3cY3);
    EC_POINT_free(z2gb);
    EC_POINT_free(z1gc);
    if (ret == 1) { //not equal
        BN_free(c);
        return 1; // verification failed
    }
    
    BN_free(c);
    return 0; //successful verification
    
}

int nizk_reshare_test_1(int print) {
    
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    
    BIGNUM *w1 = BN_new();
    BIGNUM *w2 = BN_new();
    EC_POINT *ga = random_point(group, ctx);
    EC_POINT *gb = random_point(group, ctx);
    EC_POINT *gc = random_point(group, ctx);
    EC_POINT *Y1 = EC_POINT_new(group);
    EC_POINT *Y2 = EC_POINT_new(group);
    EC_POINT *Y3 = EC_POINT_new(group);
    EC_POINT *w2gb = EC_POINT_new(group);
    EC_POINT *w1gc = EC_POINT_new(group);
    
    BN_dec2bn(&w1, "5");
    BN_dec2bn(&w2, "7");
    point_mul(group, Y1, w1, ga, ctx);
    point_mul(group, Y2, w2, ga, ctx);
    point_mul(group, w2gb, w2, gb, ctx);
    point_mul(group, w1gc, w1, gc, ctx);
    point_sub(group, Y3, w2gb, w1gc, ctx);
    
    nizk_reshare_proof pi;
    nizk_reshare_prove(group, w1, w2, ga, gb, gc, Y1, Y2, Y3, &pi, ctx);
    int ret1 = nizk_reshare_verify(group, ga, gb, gc, Y1, Y2, Y3, &pi, ctx);

    if (print) {
        printf("Test 1 part 1 %s: Correct NIZK Reshare Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }
    
    BN_free(w1);
    BN_free(w2);
    EC_POINT_free(ga);
    EC_POINT_free(gb);
    EC_POINT_free(gc);
    EC_POINT_free(Y1);
    EC_POINT_free(Y2);
    EC_POINT_free(Y3);
    EC_POINT_free(w2gb);
    EC_POINT_free(w1gc);
 
    return !ret1;
}

int nizk_reshare_test_2(int print) {
    return 0; // test passed
}

typedef int (*test_function)(int);

static test_function test_suite[] = {
    &nizk_reshare_test_1,
    &nizk_reshare_test_2
};

int nizk_reshare_test_suite(int print) {
    int num_tests = sizeof(test_suite)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite[i](print)) {
            ret = 1;
        }
    }
    return ret;
}
