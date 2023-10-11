//
//  nizk_reshare.c
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-09-29.
//
#include "nizk_reshare.h"
#include <assert.h>
#include "openssl_hashing_tools.h"

static int num_initialized = 0;
static int num_freed = 0;

void nizk_reshare_print_allocation_status(void) {
    printf("nizk_reshare: initalized %d, freed %d (%d diff)\n", num_initialized, num_freed, num_initialized - num_freed);
}

void nizk_reshare_proof_free(nizk_reshare_proof *pi) {
    assert(pi && "nizk_reshare_proof_free: usage error, no proof passed");
    assert(pi->R1 && "nizk_reshare_proof_free: usage error, R1 is NULL");
    assert(pi->R2 && "nizk_reshare_proof_free: usage error, R2 is NULL");
    assert(pi->R3 && "nizk_reshare_proof_free: usage error, R3 is NULL");
    assert(pi->z1 && "nizk_reshare_proof_free: usage error, z1 is NULL");
    assert(pi->z2 && "nizk_reshare_proof_free: usage error, z2 is NULL");
    point_free(pi->R1);
    pi->R1 = NULL; // superflous safety
    point_free(pi->R2);
    pi->R2 = NULL; // superflous safety
    point_free(pi->R3);
    pi->R3 = NULL; // superflous safety
    bn_free(pi->z1);
    pi->z1 = NULL; // superflous safety
    bn_free(pi->z2);
    pi->z2 = NULL; // superflous safety
    num_freed++;
}

void nizk_reshare_prove(const EC_GROUP *group, const BIGNUM *w1, const BIGNUM *w2, const EC_POINT *ga, const EC_POINT *gb, const EC_POINT *gc, const EC_POINT *Y1, const EC_POINT *Y2, const EC_POINT *Y3, nizk_reshare_proof *pi, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);

    // compute R1, R2, R3
    BIGNUM *r1 = bn_random(order, ctx);
    BIGNUM *r2 = bn_random(order, ctx);
    pi->R1 = point_new(group);
    point_mul(group, pi->R1, r1, ga, ctx);
    pi->R2 = point_new(group);
    point_mul(group, pi->R2, r2, ga, ctx);
    EC_POINT *gb_r2 = point_new(group);
    point_mul(group, gb_r2, r2, gb, ctx);
    EC_POINT *gc_r1 = point_new(group);
    point_mul(group, gc_r1, r1, gc, ctx);
    pi->R3 = point_new(group);
    point_sub(group, pi->R3, gb_r2, gc_r1, ctx);

    // compute c
    BIGNUM *c = openssl_hash_points2bn(group, ctx, 9, ga, gb, gc, Y1, Y2, Y3, pi->R1, pi->R2, pi->R3);

    // compute z1, z2
    pi->z1 = bn_new();
    BN_mod_mul(pi->z1, c, w1, order, ctx);
    BN_mod_add(pi->z1, pi->z1, r1, order, ctx); // r1 + c * w1

    pi->z2 = bn_new();
    BN_mod_mul(pi->z2, c, w2, order, ctx);
    BN_mod_add(pi->z2, pi->z2, r2, order, ctx); // r2 + c * w2

    // cleanup
    point_free(gc_r1);
    point_free(gb_r2);
    bn_free(c);
    bn_free(r2);
    bn_free(r1);
    
    num_initialized++;
    // implicitly return proof pi
}

int nizk_reshare_verify(const EC_GROUP *group, const EC_POINT *ga, const EC_POINT *gb, const EC_POINT *gc, const EC_POINT *Y1, const EC_POINT *Y2, const EC_POINT *Y3, const nizk_reshare_proof *pi, BN_CTX *ctx) {
    // compute c
    BIGNUM *c = openssl_hash_points2bn(group, ctx, 9, ga, gb, gc, Y1, Y2, Y3, pi->R1, pi->R2, pi->R3);

    // check dl for Y1
    EC_POINT *cY1 = point_new(group);
    point_mul(group, cY1, c, Y1, ctx);
    EC_POINT *R1cY1 = point_new(group);
    point_add(group, R1cY1, pi->R1, cY1, ctx);
    EC_POINT *z1ga = point_new(group);
    point_mul(group, z1ga, pi->z1, ga, ctx);
    int ret1 = point_cmp(group, R1cY1, z1ga, ctx);
    
    // check dl for Y2
    EC_POINT *cY2 = point_new(group);
    point_mul(group, cY2, c, Y2, ctx);
    EC_POINT *R2cY2 = point_new(group);
    point_add(group, R2cY2, pi->R2, cY2, ctx);
    EC_POINT *z2ga = point_new(group);
    point_mul(group, z2ga, pi->z2, ga, ctx);
    int ret2 = point_cmp(group, R2cY2, z2ga, ctx);

    // check pedersen commitment for Y3
    EC_POINT *cY3 = point_new(group);
    point_mul(group, cY3, c, Y3, ctx);
    EC_POINT *R3cY3 = point_new(group);
    point_add(group, R3cY3, pi->R3, cY3, ctx);
    EC_POINT *z2gb = point_new(group);
    point_mul(group, z2gb, pi->z2, gb, ctx);
    EC_POINT *z1gc = point_new(group);
    point_mul(group, z1gc, pi->z1, gc, ctx);
    EC_POINT *z2gb_z1gc = point_new(group);
    point_sub(group, z2gb_z1gc, z2gb, z1gc, ctx);
    int ret3 = point_cmp(group, R3cY3, z2gb_z1gc, ctx);

    // cleanup
    point_free(z2gb_z1gc);
    point_free(z1gc);
    point_free(z2gb);
    point_free(R3cY3);
    point_free(cY3);
    point_free(z2ga);
    point_free(R2cY2);
    point_free(cY2);
    point_free(z1ga);
    point_free(R1cY1);
    point_free(cY1);
    bn_free(c);

    return !(ret1 == 0 && ret2 == 0 & ret3 == 0);
}

int nizk_reshare_test_1(int print) {
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();

    // allocate temp variables
    BIGNUM *w1 = bn_new();
    BIGNUM *w2 = bn_new();
    EC_POINT *ga = point_random(group, ctx);
    EC_POINT *gb = point_random(group, ctx);
    EC_POINT *gc = point_random(group, ctx);
    EC_POINT *Y1 = point_new(group);
    EC_POINT *Y2 = point_new(group);
    EC_POINT *Y3 = point_new(group);
    EC_POINT *w2gb = point_new(group);
    EC_POINT *w1gc = point_new(group);

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
        printf("%6s Test 1: Correct NIZK Reshare Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // cleanup
    nizk_reshare_proof_free(&pi);
    bn_free(w1);
    bn_free(w2);
    point_free(ga);
    point_free(gb);
    point_free(gc);
    point_free(Y1);
    point_free(Y2);
    point_free(Y3);
    point_free(w2gb);
    point_free(w1gc);
    BN_CTX_free(ctx);
 
    return ret1 != 0;
}

int nizk_reshare_test_2(int print) {
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();

    // allocate temp variables
    BIGNUM *w1 = bn_new();
    BIGNUM *w2 = bn_new();
    EC_POINT *ga = point_random(group, ctx);
    EC_POINT *gb = point_random(group, ctx);
    EC_POINT *gc = point_random(group, ctx);
    EC_POINT *Y1 = point_new(group);
    EC_POINT *Y2 = point_new(group);
    EC_POINT *Y3 = point_new(group);
    EC_POINT *w2gb = point_new(group);
    EC_POINT *w1gc = point_new(group);
    
    BN_dec2bn(&w1, "5");
    BN_dec2bn(&w2, "7");
    point_mul(group, Y1, w1, ga, ctx);
    point_mul(group, Y2, w2, ga, ctx);
    point_mul(group, w2gb, w2, gb, ctx);
    point_mul(group, w1gc, w1, gc, ctx);
    point_sub(group, Y3, w2gb, w1gc, ctx);
    
    //positive test

    // verify correct reshare
    nizk_reshare_proof pi;
    nizk_reshare_prove(group, w1, w2, ga, gb, gc, Y1, Y2, Y3, &pi, ctx);
    int ret1 = nizk_reshare_verify(group, ga, gb, gc, Y1, Y2, Y3, &pi, ctx);

    if (print) {
        printf("%6s Test 2 - 1: Correct NIZK Reshare Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }
    
    //negative tests
    EC_POINT *bad = point_random(group, ctx);

    int neg_rets[6];
    neg_rets[0] = nizk_reshare_verify(group, bad, gb, gc, Y1, Y2, Y3, &pi, ctx);
    neg_rets[1] = nizk_reshare_verify(group, ga, bad, gc, Y1, Y2, Y3, &pi, ctx);
    neg_rets[2] = nizk_reshare_verify(group, ga, gb, bad, Y1, Y2, Y3, &pi, ctx);
    neg_rets[3] = nizk_reshare_verify(group, ga, gb, gc, bad, Y2, Y3, &pi, ctx);
    neg_rets[4] = nizk_reshare_verify(group, ga, gb, gc, Y1, bad, Y3, &pi, ctx);
    neg_rets[5] = nizk_reshare_verify(group, ga, gb, gc, Y1, Y2, bad, &pi, ctx);
    
    int neg_ret_sum = 0;
    for (int i = 0; i < 6; i++) {
        if (print) {
            if (neg_rets[i]) {
                neg_ret_sum++;
                printf("    OK Test 2 - %d: Incorrect NIZK Reshare Proof not accepted (which is CORRECT)\n",i+2);
            } else {
                printf("NOT OK Test 2 - %d: Incorrect NIZK Reshare Proof IS accepted (which is an ERROR)\n",i+2);
            }
        }
    }
    
    // cleanup
    nizk_reshare_proof_free(&pi);
    bn_free(w1);
    bn_free(w2);
    point_free(ga);
    point_free(gb);
    point_free(gc);
    point_free(Y1);
    point_free(Y2);
    point_free(Y3);
    point_free(w2gb);
    point_free(w1gc);
    point_free(bad);
    BN_CTX_free(ctx);
    
    return ret1 != 0 && neg_ret_sum == 6;
}

typedef int (*test_function)(int);

static test_function test_suite[] = {
    &nizk_reshare_test_1,
    &nizk_reshare_test_2
};

int nizk_reshare_test_suite(int print) {
    if (print) {
        printf("NIZK RESHARE test suite\n");
    }
    int num_tests = sizeof(test_suite)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite[i](print)) {
            ret = 1;
        }
    }
    if (print) {
        print_allocation_status();
        nizk_reshare_print_allocation_status();
        fflush(stdout);
    }
    return ret;
}
