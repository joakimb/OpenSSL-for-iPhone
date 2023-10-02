//
//  dh_pvss.h
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-10-01.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#ifndef dh_pvss_h
#define dh_pvss_h

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
} dh_pvss_params;

typedef struct {
    BIGNUM *priv;
    EC_POINT *pub;
} key_pair;

void dh_pvss_params_free(dh_pvss_params *pp);

void key_pair_free(key_pair *kp);

dh_pvss_params *setup(const int t, const int n, BN_CTX *ctx);

void key_gen(key_pair *kp, BN_CTX *ctx);

void prove_key_pair(key_pair *kp, nizk_dl_proof *pi, BN_CTX *ctx);

int verify_pub_key(const EC_POINT *pubKey, const nizk_dl_proof *pi, BN_CTX *ctx);

int dh_pvss_test_suite(int print);

#endif /* dh_pvss_h */


