//
//  openssl_hashing_tools.h
//
//  Created by Paul Stankovski Wagner on 2023-09-27.
//

#ifndef OPENSSL_HASHING_TOOLS_H
#define OPENSSL_HASHING_TOOLS_H
#include <openssl/sha.h>
#include "P256.h"

void openssl_hash_init(SHA256_CTX *sha_ctx);
void openssl_hash_update(SHA256_CTX *sha_ctx, const void *data, size_t len);
void openssl_hash_update_bignum(SHA256_CTX *sha_ctx, const BIGNUM *bn, BN_CTX *bn_ctx);
void openssl_hash_update_point(SHA256_CTX *sha_ctx, const EC_GROUP *group, const EC_POINT *point, BN_CTX *bn_ctx);
void openssl_hash_final(unsigned char *md, SHA256_CTX *sha_ctx);
void openssl_hash(const unsigned char*buf, size_t buf_len, unsigned char *hash);
BIGNUM *openssl_hash2bignum(const unsigned char *md);

BIGNUM *openssl_hash_ppp2bn(const EC_GROUP *group, const EC_POINT *p1, const EC_POINT *p2, const EC_POINT *p3, BN_CTX *bn_ctx);
BIGNUM *openssl_hash_pppppp2bn(const EC_GROUP *group, const EC_POINT *p1, const EC_POINT *p2, const EC_POINT *p3, const EC_POINT *p4, const EC_POINT *p5, const EC_POINT *p6, BN_CTX *bn_ctx);
BIGNUM *openssl_hash_ppppppppp2bn(const EC_GROUP *group, const EC_POINT *p1, const EC_POINT *p2, const EC_POINT *p3, const EC_POINT *p4, const EC_POINT *p5, const EC_POINT *p6, const EC_POINT *p7, const EC_POINT *p8, const EC_POINT *p9, BN_CTX *bn_ctx);

#endif
