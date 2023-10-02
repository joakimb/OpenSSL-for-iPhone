//
//  DH_PVSS.h
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-10-01.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#ifndef DH_PVSS_h
#define DH_PVSS_h

#include <stdio.h>
#include "P256.h"

typedef struct {
    int t;
    int n;
    BIGNUM **alphas;
    BIGNUM **betas;
    BIGNUM **vs;
    BIGNUM **v_primes;
} DH_PVSS_params;

typedef struct {
    BIGNUM *priv;
    EC_POINT *pub;
} KEY_PAIR;

void DH_PVSS_params_free(DH_PVSS_params *pp);

DH_PVSS_params *setup(const int t, const int n, BN_CTX *ctx);

int DH_PVSS_test_suite(int print);

#endif /* DH_PVSS_h */


