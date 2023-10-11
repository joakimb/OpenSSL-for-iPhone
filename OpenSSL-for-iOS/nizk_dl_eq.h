//
//  nizk_dl_eq.h
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-09-29.
//

#ifndef NIZK_DL_EQ_H
#define NIZK_DL_EQ_H
#include "P256.h"

typedef struct {
    EC_POINT *Ra;
    EC_POINT *Rb;
    BIGNUM *z;
} nizk_dl_eq_proof;

void nizk_dl_eq_prove(const EC_GROUP *group, const BIGNUM *exp, const EC_POINT *a, const EC_POINT *A, const EC_POINT *b, const EC_POINT *B, nizk_dl_eq_proof *pi, BN_CTX *ctx);
int nizk_dl_eq_verify(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *A, const EC_POINT *b, const EC_POINT *B, const nizk_dl_eq_proof *pi, BN_CTX *ctx);
void nizk_dl_eq_proof_free(nizk_dl_eq_proof *pi);

int nizk_dl_eq_test_suite(int print);
#ifdef DEBUG
void nizk_dl_eq_print_allocation_status(void);
#endif

#endif /* NIZK_DL_EQ_H */
