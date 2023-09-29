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
// TODO:    EC_POINT_sub(group, pi->R3, gb_r2, gc_r1, ctx); // implement

    BIGNUM *c = openssl_hash_ppppppppp2bn(group, ga, gb, gc, Y1, Y2, Y3, pi->R1, pi->R2, pi->R3, ctx);

    pi->z1 = BN_new();
    BN_mod_mul(pi->z1, c, w1, order, ctx);
    BN_mod_add(pi->z1, pi->z1, r1, order, ctx); // pi->z1 = (r1 + c * w1).mod(domain.order)

    pi->z2 = BN_new();
    BN_mod_mul(pi->z2, c, w2, order, ctx);
    BN_mod_add(pi->z2, pi->z2, r2, order, ctx); // pi->z2 = (r2 + c * w2).mod(domain.order)
    // implicitly return proof pi
}

int nizk_reshare_verify(const EC_GROUP *group, const EC_POINT *ga, const EC_POINT *gb, const EC_POINT *gc, const EC_POINT *Y1, const EC_POINT *Y2, const EC_POINT *Y3, const nizk_reshare_proof *pi, BN_CTX *ctx) {
    return 1; // verification failed, not implemented
}

#if 0
//prove knowledge of w_1 and w_2 so that Y_1 = g_a^w_1 && Y_2 = g_a^w_2 && Y_3 = (g_b^w_2 * g_c ^ -w_1), note that Y3 is a pedersen commitment
func NIZKReshareProve(w1: BInt, w2: BInt, ga: Point, gb: Point, gc: Point, Y1: Point, Y2: Point, Y3: Point) throws -> ReshareProof {
    
    let r1 = randZp()
    let r2 = randZp()
    let R1 = try domain.multiplyPoint(ga, r1)
    let R2 = try domain.multiplyPoint(ga, r2)
    let gbr2 = try domain.multiplyPoint(gb, r2)
    let gcr1 = try domain.multiplyPoint(gc, r1)
    let R3 = try domain.subtractPoints(gbr2, gcr1)
    
    let bytes = toBytes(ga) + toBytes(gb) + toBytes(gc) + toBytes(Y1) + toBytes(Y2) + toBytes(Y3) + toBytes(R1) + toBytes(R2) + toBytes(R3)
    let c = sha256(bytes).mod(domain.order)
    
    let z1 = (r1 + c * w1).mod(domain.order)
    let z2 = (r2 + c * w2).mod(domain.order)
    
    return ReshareProof(R1: R1, R2: R2, R3: R3, z1: z1, z2: z2)

}

func NIZKReshareVerify(ga: Point, gb: Point, gc: Point, Y1: Point, Y2: Point, Y3: Point, pi: ReshareProof) throws -> Bool {
    
    let bytes = toBytes(ga) + toBytes(gb) + toBytes(gc) + toBytes(Y1) + toBytes(Y2) + toBytes(Y3) + toBytes(pi.R1) + toBytes(pi.R2) + toBytes(pi.R3)
    let c = sha256(bytes).mod(domain.order)
    
    //check dl for Y1
    let cY1 = try domain.multiplyPoint(Y1, c)
    let R1cY1 = try domain.addPoints(pi.R1, cY1)
    let z1ga = try domain.multiplyPoint(ga, pi.z1)
    let DLcheck1 = (R1cY1 == z1ga)
    
    //check dl for Y2
    let cY2 = try domain.multiplyPoint(Y2, c)
    let R2cY2 = try domain.addPoints(pi.R2, cY2)
    let z2ga = try domain.multiplyPoint(ga, pi.z2)
    let DLcheck2 = (R2cY2 == z2ga)
    
    //check pedersen commitment for Y3
    let cY3 = try domain.multiplyPoint(Y3, c)
    let R3cY3 = try domain.addPoints(pi.R3, cY3)
    let z2gb = try domain.multiplyPoint(gb, pi.z2)
    let z1gc = try domain.multiplyPoint(gc, pi.z1)
    let z2gb_z1gc = try domain.subtractPoints(z2gb, z1gc)
    let pedersencheck = (R3cY3 == z2gb_z1gc)
    
    return (DLcheck1 && DLcheck2 && pedersencheck)
    
}
#endif

int nizk_reshare_test_1(int print) {
    return 0; // test passed
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
