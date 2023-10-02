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

BIGNUM *openssl_hash_points2bn(const EC_GROUP *group, BN_CTX *bn_ctx, int num_points,...);

#endif
