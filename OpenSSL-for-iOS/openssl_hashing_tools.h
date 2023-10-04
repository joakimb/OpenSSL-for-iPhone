//
//  openssl_hashing_tools.h
//
//  Created by Paul Stankovski Wagner on 2023-09-27.
//

#ifndef OPENSSL_HASHING_TOOLS_H
#define OPENSSL_HASHING_TOOLS_H
#include <openssl/sha.h>
#include "P256.h"

// generic helpers
void openssl_hash_init(SHA256_CTX *sha_ctx);
void openssl_hash_update(SHA256_CTX *sha_ctx, const void *data, size_t len);
void openssl_hash_update_bignum(SHA256_CTX *sha_ctx, const BIGNUM *bn);
void openssl_hash_update_point(SHA256_CTX *sha_ctx, const EC_GROUP *group, const EC_POINT *point, BN_CTX *bn_ctx);
void openssl_hash_final(unsigned char *md, SHA256_CTX *sha_ctx);
void openssl_hash(const unsigned char*buf, size_t buf_len, unsigned char *hash);
BIGNUM *openssl_hash2bignum(const unsigned char *md);

// hashing BIGNUMs
BIGNUM *openssl_hash_bn2bn(const BIGNUM *bn);
BIGNUM *openssl_hash_bns2bn(int num_bns,...);
BIGNUM *openssl_hash_bn_list2bn(int num_bns, const BIGNUM *bn_list[]);

// hashing points
BIGNUM *openssl_hash_point2bn(const EC_GROUP *group, BN_CTX *bn_ctx, const EC_POINT *point);
BIGNUM *openssl_hash_points2bn(const EC_GROUP *group, BN_CTX *bn_ctx, int num_points,...);
BIGNUM *openssl_hash_point_list2bn(const EC_GROUP *group, BN_CTX *bn_ctx, int list_len, const EC_POINT *point_list[]);
BIGNUM *openssl_hash_point_lists2bn(const EC_GROUP *group, BN_CTX *bn_ctx, int num_lists, int *list_len, const EC_POINT **point_list[]);

// hash points to polynomial
void openssl_hash_points2poly(const EC_GROUP *group, BN_CTX *ctx, int num_coeffs, BIGNUM *poly_coeff[], int num_point_lists, int *num_points, const EC_POINT ***point_list);

#endif
