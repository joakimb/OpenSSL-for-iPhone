//
//  openssl_hashing_tools.c
//
//  Created by Paul Stankovski Wagner on 2023-09-27.
//
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include "openssl_hashing_tools.h"

void openssl_hash_init(SHA256_CTX *ctx) {
    SHA256_Init(ctx);
}

void openssl_hash_update(SHA256_CTX *ctx, const void *data, size_t len) {
    SHA256_Update(ctx, data, len);
}

void openssl_hash_update_bignum(SHA256_CTX *sha_ctx, const BIGNUM *bn, BN_CTX *bn_ctx) {
    assert(0 && "openssl_hash_update_bignum not implemented yet");
}

void openssl_hash_update_point(SHA256_CTX *sha_ctx, const EC_GROUP *group, const EC_POINT *point, BN_CTX *bn_ctx) {
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL); // note, switch to compressed to minimize hashing time
    size_t buf_size = len + 1;
    unsigned char *buf = malloc(buf_size);
    assert(buf && "ec_points_hash: allocation error");
    const unsigned char sentinel = 0xac;
    buf[len] = sentinel;
    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buf, len, bn_ctx); // note, switch to compressed to minimize hashing time
    if (buf[len] != sentinel) {
        assert(0 && "ec_points_hash: sentinel overwritten");
    }
    SHA256_Update(sha_ctx, buf, len); // excluding sentinel
    free(buf); // note, switch to static allocation
}

void openssl_hash_final(unsigned char *md, SHA256_CTX *ctx) {
    SHA256_Final(md, ctx);
}

void openssl_hash(const unsigned char*buf, size_t buf_len, unsigned char *md) {
    SHA256(buf, buf_len, md);
}

BIGNUM *openssl_hash2bignum(const unsigned char *md) {
    return BN_bin2bn(md, SHA256_DIGEST_LENGTH, NULL); // convert/map hash digest to BIGNUM, note
}

BIGNUM *openssl_hash_points2bn(const EC_GROUP *group, BN_CTX *bn_ctx, int num_points,...) {
    va_list vl;
    va_start(vl, num_points);

    SHA256_CTX sha_ctx;
    openssl_hash_init(&sha_ctx);
    for (int i=0; i<num_points; i++) {
        const EC_POINT *point = va_arg(vl, const EC_POINT*);
        openssl_hash_update_point(&sha_ctx, group, point, bn_ctx);
    }
    va_end(vl);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    openssl_hash_final(hash, &sha_ctx);
    BIGNUM *bn = openssl_hash2bignum(hash);
    return bn;
}
