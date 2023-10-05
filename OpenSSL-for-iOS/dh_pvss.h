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
#include "nizk_dl_eq.h"
#include "nizk_reshare.h"

typedef struct {
    const EC_GROUP *group;
    BN_CTX *bn_ctx;
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
void dh_pvss_distribute_prove(dh_pvss_ctx *pp, EC_POINT **enc_shares, dh_key_pair *dist_key, const EC_POINT *com_keys[], EC_POINT *secret, nizk_dl_eq_proof *pi);
int dh_pvss_distribute_verify(dh_pvss_ctx *pp, nizk_dl_eq_proof *pi, const EC_POINT **enc_shares, const EC_POINT *pub_dist, const EC_POINT **com_keys);

EC_POINT *dh_pvss_decrypt_share_prove(const EC_GROUP *group, const EC_POINT *dist_key_pub, dh_key_pair *C, const EC_POINT *encrypted_share, nizk_dl_eq_proof *pi, BN_CTX *ctx);
int dh_pvss_decrypt_share_verify(const EC_GROUP *group, const EC_POINT *dist_key_pub, const EC_POINT *C_pub, const EC_POINT *encrypted_share, const EC_POINT *decrypted_share, nizk_dl_eq_proof *pi, BN_CTX *ctx);
EC_POINT *dh_pvss_reconstruct(const EC_GROUP *group, const EC_POINT *shares[], int share_indices[], int t, int length, BN_CTX *ctx);
EC_POINT *dh_pvss_committee_dist_key_calc(const EC_GROUP *group, const EC_POINT *keys[], int key_indices[], int t, int length, BN_CTX *ctx);
void dh_pvss_reshare_prove(const EC_GROUP *group, int party_index, const dh_key_pair *party_committee_kp, const dh_key_pair *party_dist_kp, const EC_POINT *previous_dist_key, const EC_POINT *current_enc_shares[], const int current_n, const dh_pvss_ctx *next_pp, const EC_POINT *next_committee_keys[], EC_POINT *enc_re_shares[], nizk_reshare_proof *pi, BN_CTX *ctx);
int dh_pvss_reshare_verify(const dh_pvss_ctx *pp, const dh_pvss_ctx *next_pp, int party_index, const EC_POINT *party_committee_pub_key, const EC_POINT *party_dist_pub_key, const EC_POINT *previous_dist_key, const EC_POINT *current_enc_shares[], const EC_POINT *next_committee_keys[], EC_POINT *enc_re_shares[], nizk_reshare_proof *pi);
EC_POINT *dh_pvss_reconstruct_reshare(const dh_pvss_ctx *pp, int num_valid_indices, int *valid_indices, EC_POINT *enc_re_shares[]);

int dh_pvss_test_suite(int print);


#endif /* dh_pvss_h */
