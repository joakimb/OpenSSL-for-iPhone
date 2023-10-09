//
//  nizk_reshare.h
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-09-29.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#ifndef NIZK_RESHARE_H
#define NIZK_RESHARE_H
#include "P256.h"

typedef struct {
    EC_POINT *R1;
    EC_POINT *R2;
    EC_POINT *R3;
    BIGNUM *z1;
    BIGNUM *z2;
} nizk_reshare_proof;

void nizk_reshare_prove(const EC_GROUP *group, const BIGNUM *w1, const BIGNUM *w2, const EC_POINT *ga, const EC_POINT *gb, const EC_POINT *gc, const EC_POINT *Y1, const EC_POINT *Y2, const EC_POINT *Y3, nizk_reshare_proof *pi, BN_CTX *ctx);
int nizk_reshare_verify(const EC_GROUP *group, const EC_POINT *ga, const EC_POINT *gb, const EC_POINT *gc, const EC_POINT *Y1, const EC_POINT *Y2, const EC_POINT *Y3, const nizk_reshare_proof *pi, BN_CTX *ctx);
void nizk_reshare_proof_free(nizk_reshare_proof *pi);
int nizk_reshare_test_suite(int print);

void nizk_reshare_print_allocation_status(void);

#endif /* NIZK_RESHARE_H */
