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
#include "nizk_dl.h"

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
} key_pair;

void DH_PVSS_params_free(DH_PVSS_params *pp);

void key_pair_free(key_pair *kp);

DH_PVSS_params *setup(const int t, const int n, BN_CTX *ctx);

void key_gen(key_pair *kp, BN_CTX *ctx);

void prove_key_pair(key_pair *kp, nizk_dl_proof *pi, BN_CTX *ctx);

int verify_pub_key(const EC_POINT *pubKey, const nizk_dl_proof *pi, BN_CTX *ctx);

int DH_PVSS_test_suite(int print);

#endif /* DH_PVSS_h */


