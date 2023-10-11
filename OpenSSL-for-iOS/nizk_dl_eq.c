//
//  nizk_dl_eq.c
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-09-29.
//
#include "nizk_dl_eq.h"
#include <assert.h>
#include "openssl_hashing_tools.h"

#ifdef DEBUG
static int num_initialized = 0;
static int num_freed = 0;

void nizk_dl_eq_print_allocation_status(void) {
    printf("nizk_dl_eq: initalized %d, freed %d (%d diff)\n", num_initialized, num_freed, num_initialized - num_freed);
}
#endif

void nizk_dl_eq_proof_free(nizk_dl_eq_proof *pi) {
    assert(pi && "nizk_dl_eq_proof_free: usage error, no proof passed");
    assert(pi->Ra && "nizk_dl_eq_proof_free: usage error, Ra is NULL");
    assert(pi->Rb && "nizk_dl_eq_proof_free: usage error, Rb is NULL");
    assert(pi->z && "nizk_dl_eq_proof_free: usage error, z is NULL");
    point_free(pi->Ra);
    pi->Ra = NULL; // superflous safety
    point_free(pi->Rb);
    pi->Rb = NULL; // superflous safety
    bn_free(pi->z);
    pi->z = NULL; // superflous safety
#ifdef DEBUG
    num_freed++;
#endif
}

void nizk_dl_eq_prove(const EC_GROUP *group, const BIGNUM *exp, const EC_POINT *a, const EC_POINT *A, const EC_POINT *b, const EC_POINT *B, nizk_dl_eq_proof *pi, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);

    // compute Ra
    BIGNUM *r = bn_random(order, ctx); // draw r uniformly at random
    pi->Ra = point_new(group);
    point_mul(group, pi->Ra, r, a, ctx);

    // compute Rb
    pi->Rb = point_new(group);
    point_mul(group, pi->Rb, r, b, ctx);

    // compute c
    BIGNUM *c = openssl_hash_points2bn(group, ctx, 6, a, A, b, B, pi->Ra, pi->Rb);

    // compute z
    pi->z = bn_new();
    int ret = BN_mod_mul(pi->z, c, exp, order, ctx);
    assert(ret == 1 && "nizk_dl_eq_prove: BN_mod_mul computation failed");
    ret = BN_mod_sub(pi->z, r, pi->z, order, ctx);
    assert(ret == 1 && "nizk_dl_eq_prove: BN_mod_sub computation failed");

    // cleanup
    bn_free(c);
    bn_free(r);
    
#ifdef DEBUG
    num_initialized++;
#endif
    /* implicitly return pi = (Ra, Rb, z) */
}

int nizk_dl_eq_verify(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *A, const EC_POINT *b, const EC_POINT *B, const nizk_dl_eq_proof *pi, BN_CTX *ctx) {
    // compute c
    BIGNUM *c = openssl_hash_points2bn(group, ctx, 6, a, A, b, B, pi->Ra, pi->Rb);

    /* check if pi->Ra = [pi->z]a + [c]A */
    EC_POINT *Ra_prime = point_new(group);
    const EC_POINT *a_points[] = { a, A };
    const BIGNUM *bns[] = { pi->z, c };
    EC_POINTs_mul(group, Ra_prime, NULL, 2, a_points, bns, ctx); // no wrapper for EC_POINTs_mul
    int ret = point_cmp(group, Ra_prime, pi->Ra, ctx);
    point_free(Ra_prime);
    if (ret == 1) { // not equal
        bn_free(c);
        return 1; // verification failed
    }

    /* check if pi->Rb = [pi->z]b + [c]B */
    EC_POINT *Rb_prime = point_new(group);
    const EC_POINT *b_points[] = { b, B };
    EC_POINTs_mul(group, Rb_prime, NULL, 2, b_points, bns, ctx); // no wrapper for EC_POINTs_mul
    ret = point_cmp(group, Rb_prime, pi->Rb, ctx);
    point_free(Rb_prime);
    if (ret == 1) { // not equal
        bn_free(c);
        return 1; // verification failed
    }

    // cleanup
    bn_free(c);

    return 0; // verification successful
}

/*
 *
 *  nizk_dl_eq tests
 *
 */
static int nizk_dl_eq_test_1(int print) {
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *exp = bn_new();
    BN_dec2bn(&exp, "7");
    BIGNUM *exp_bad = bn_new();
    BN_dec2bn(&exp_bad, "6");

    EC_POINT *a = point_random(group, ctx);
    EC_POINT *A = point_new(group);
    point_mul(group, A, exp, a, ctx);

    EC_POINT *b = point_random(group, ctx);
    EC_POINT *B = point_new(group);
    point_mul(group, B, exp, b, ctx);
    
    // produce correct proof and verify
    nizk_dl_eq_proof pi;
    nizk_dl_eq_prove(group, exp, a, A, b, B, &pi, ctx);
    int ret1 = nizk_dl_eq_verify(group, a, A, b, B, &pi, ctx);

    if (print) {
        printf("%6s Test 1 - 1: Correct NIZK DL EQ Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // negative tests
    // try to verify incorrect proof (bad B-value)
    EC_POINT *B_bad = point_new(group);
    point_mul(group, B_bad, exp_bad, b, ctx);
    int ret2 = nizk_dl_eq_verify(group, a, A, b, B_bad, &pi, ctx);
    if (print) {
        if (ret2) {
            printf("    OK Test 1 - 2: Incorrect NIZK DL EQ Proof not accepted (which is CORRECT)\n");
        } else {
            printf("NOT OK Test 1 - 2: Incorrect NIZK DL EQ Proof IS accepted (which is an ERROR)\n");
        }
    }

    // cleanup
    nizk_dl_eq_proof_free(&pi);
    point_free(a);
    point_free(A);
    point_free(b);
    point_free(B);
    point_free(B_bad);
    bn_free(exp);
    bn_free(exp_bad);
    BN_CTX_free(ctx);

    // return test results
    return !(ret1 == 0 && ret2 != 0);
}

static int nizk_dl_eq_test_2(int print) {
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *exp = bn_new();
    BN_dec2bn(&exp, "7");
    BIGNUM *exp_bad = bn_new();
    BN_dec2bn(&exp_bad, "6");

    EC_POINT *a = point_random(group, ctx);
    EC_POINT *A = point_new(group);
    point_mul(group, A, exp, a, ctx);

    EC_POINT *b = point_random(group, ctx);
    EC_POINT *B = point_new(group);
    point_mul(group, B, exp, b, ctx);
    
    // produce correct proof and verify
    nizk_dl_eq_proof pi;
    nizk_dl_eq_prove(group, exp, a, A, b, B, &pi, ctx);
    int ret1 = nizk_dl_eq_verify(group, a, A, b, B, &pi, ctx);

    if (print) {
        printf("%6s Test 2 - 1: Correct NIZK DL EQ Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // negative tests
    // try to verify incorrect proof (bad B-value)
    EC_POINT *A_bad = point_new(group);
    point_mul(group, A_bad, exp_bad, a, ctx);
    int ret2 = nizk_dl_eq_verify(group, a, A_bad, b, B, &pi, ctx);
    if (print) {
        if (ret2) {
            printf("    OK Test 2 - 2: Incorrect NIZK DL EQ Proof not accepted (which is CORRECT)\n");
        } else {
            printf("NOT OK Test 2 - 2: Incorrect NIZK DL EQ Proof IS accepted (which is an ERROR)\n");
        }
    }

    // cleanup
    nizk_dl_eq_proof_free(&pi);
    point_free(a);
    point_free(A);
    point_free(A_bad);
    point_free(b);
    point_free(B);
    bn_free(exp);
    bn_free(exp_bad);
    BN_CTX_free(ctx);

    // return test results
    return !(ret1 == 0 && ret2 != 0);
}

typedef int (*test_function)(int);

static test_function test_suite[] = {
    &nizk_dl_eq_test_1,
    &nizk_dl_eq_test_2
};

int nizk_dl_eq_test_suite(int print) {
    if (print) {
        printf("NIZK DL EQ test suite BEGIN -------------------------\n");
    }
    int num_tests = sizeof(test_suite)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite[i](print)) {
            ret = 1;
        }
    }
    if (print) {
        printf("NIZK DL EQ test suite END ---------------------------\n");
#ifdef DEBUG
        print_allocation_status();
        nizk_dl_eq_print_allocation_status();
#endif
        fflush(stdout);
    }
    return ret;
}
