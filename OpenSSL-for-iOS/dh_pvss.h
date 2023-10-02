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
#include "nizk_reshare.h"

typedef struct {
    int t;
    int n;
    BIGNUM **alphas;
    BIGNUM **betas;
    BIGNUM **vs;
    BIGNUM **v_primes;
} dh_pvss_ctx;

typedef struct {
    BIGNUM *priv;
    EC_POINT *pub;
} dh_key_pair;

void dh_key_pair_free(dh_key_pair *kp);
void dh_key_pair_generate(const EC_GROUP *group, dh_key_pair *kp, BN_CTX *ctx);
void dh_key_pair_prove(const EC_GROUP *group, dh_key_pair *kp, nizk_dl_proof *pi, BN_CTX *ctx);
int dh_pub_key_verify(const EC_GROUP *group, const EC_POINT *pub_key, const nizk_dl_proof *pi, BN_CTX *ctx);

void dh_pvss_ctx_free(dh_pvss_ctx *pp);
void dh_pvss_setup(dh_pvss_ctx *pp, const EC_GROUP *group, const int t, const int n, BN_CTX *ctx);
int dh_pvss_test_suite(int print);


#endif /* dh_pvss_h */
