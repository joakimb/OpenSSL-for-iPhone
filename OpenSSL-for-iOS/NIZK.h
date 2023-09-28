//
//  NIZK.h
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-09-19.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#ifndef NIZK_h
#define NIZK_h
#include "P256.h"

/* nizk dl */

typedef struct {
    EC_POINT *u;
    BIGNUM *z;
} nizk_dl_proof;

void nizk_dl_prove(const EC_GROUP *group, const BIGNUM *x, nizk_dl_proof *pi, BN_CTX *ctx);
int nizk_dl_verify(const EC_GROUP *group, const EC_POINT *X, const nizk_dl_proof *pi, BN_CTX *ctx);
void nizk_dl_proof_free(nizk_dl_proof *pi);
int nizk_dl_test_suite(int print);


/* nizk dl eq */

typedef struct {
    EC_POINT *Ra;
    EC_POINT *Rb;
    BIGNUM *z;
} nizk_dl_eq_proof;

void nizk_dl_eq_prove(const EC_GROUP *group, const BIGNUM *exp, const EC_POINT *a, const EC_POINT *A, const EC_POINT *b, const EC_POINT *B, nizk_dl_eq_proof *pi, BN_CTX *ctx);
int nizk_dl_eq_verify(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *A, const EC_POINT *b, const EC_POINT *B, const nizk_dl_eq_proof *pi, BN_CTX *ctx);
void nizk_dl_eq_proof_free(nizk_dl_eq_proof *pi);
int nizk_dl_eq_test_suite(int print);

#endif /* NIZK_h */
