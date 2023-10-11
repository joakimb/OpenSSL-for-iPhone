//
//  dh_key_pair.h
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-10-07.
//
#ifndef DH_KEY_PAIR_H
#define DH_KEY_PAIR_H
#include "nizk_dl.h"

typedef struct {
    BIGNUM *priv;
    EC_POINT *pub;
} dh_key_pair;

void dh_key_pair_free(dh_key_pair *kp);
void dh_key_pair_generate(const EC_GROUP *group, dh_key_pair *kp, BN_CTX *ctx);

void dh_key_pair_prove(const EC_GROUP *group, dh_key_pair *kp, nizk_dl_proof *pi, BN_CTX *ctx);
int dh_pub_key_verify(const EC_GROUP *group, const EC_POINT *pub_key, const nizk_dl_proof *pi, BN_CTX *ctx);

#endif /* DH_KEY_PAIR_H */
