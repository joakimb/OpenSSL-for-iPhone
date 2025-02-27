//
//  nizk_dl.h
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-09-29.
//

#ifndef NIZK_DL_H
#define NIZK_DL_H
#include "P256.h"

typedef struct {
    EC_POINT *u;
    BIGNUM *z;
} nizk_dl_proof;

void nizk_dl_prove(const EC_GROUP *group, const BIGNUM *x, nizk_dl_proof *pi, BN_CTX *ctx);
int nizk_dl_verify(const EC_GROUP *group, const EC_POINT *X, const nizk_dl_proof *pi, BN_CTX *ctx);
void nizk_dl_proof_free(nizk_dl_proof *pi);

int nizk_dl_test_suite(int print);
#ifdef DEBUG
void nizk_dl_print_allocation_status(void);
#endif

#endif /* NIZK_DL_H */
