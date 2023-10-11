//
//  dh_key_pair.c
//  OpenSSL-for-iOS
//
//  Created by Paul Stankovski Wagner on 2023-10-07.
//

#include "dh_key_pair.h"

void dh_key_pair_free(dh_key_pair *kp) {
    bn_free(kp->priv);
    point_free(kp->pub);
}

void dh_key_pair_generate(const EC_GROUP *group, dh_key_pair *kp, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);
    kp->priv = bn_random(order, ctx);
    kp->pub = bn2point(group, kp->priv, ctx);
}

void dh_key_pair_prove(const EC_GROUP *group, dh_key_pair *kp, nizk_dl_proof *pi, BN_CTX *ctx) {
    nizk_dl_prove(group, kp->priv, pi, ctx);
}

int dh_pub_key_verify(const EC_GROUP *group, const EC_POINT *pub_key, const nizk_dl_proof *pi, BN_CTX *ctx) {
    return nizk_dl_verify(group, pub_key, pi, ctx);
}
