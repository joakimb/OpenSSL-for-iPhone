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

void openssl_hash_update_bignum(SHA256_CTX *sha_ctx, const BIGNUM *bn) {
    assert(bn && "openssl_hash_update_bignum: expected bignum to be passed");
    int len = BN_num_bytes(bn);
    assert(len > 0 && "openssl_hash_update_bignum: unexpected length");
    size_t buf_size = len + 1;
    unsigned char buf[buf_size];
    const unsigned char sentinel = 0xac;
    buf[len] = sentinel;
    BN_bn2bin(bn, buf);
    if (buf[len] != sentinel) {
        assert(0 && "openssl_hash_update_bignum: sentinel overwritten");
    }
    SHA256_Update(sha_ctx, buf, len); // excluding sentinel
}

void openssl_hash_update_point(SHA256_CTX *sha_ctx, const EC_GROUP *group, const EC_POINT *point, BN_CTX *bn_ctx) {
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    assert(len > 0 && "openssl_hash_update_point: unexpected length");
    size_t buf_size = len + 1;
    unsigned char buf[buf_size];
    const unsigned char sentinel = 0xac;
    buf[len] = sentinel;
    EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, buf, len, bn_ctx);
    if (buf[len] != sentinel) {
        assert(0 && "ec_points_hash: sentinel overwritten");
    }
    SHA256_Update(sha_ctx, buf, len); // excluding sentinel
}

void openssl_hash_final(unsigned char *md, SHA256_CTX *ctx) {
    SHA256_Final(md, ctx);
}

void openssl_hash(const unsigned char *buf, size_t buf_len, unsigned char *md) {
    SHA256(buf, buf_len, md);
}

BIGNUM *openssl_hash2bignum(const unsigned char *md) {
    return bn_from_binary_data(SHA256_DIGEST_LENGTH, md);
}

BIGNUM *openssl_hash_bn2bn(const BIGNUM *bn) {
    return openssl_hash_bns2bn(1, bn);
}

BIGNUM *openssl_hash_bns2bn(int num_bns,...) {
    va_list vl;
    va_start(vl, num_bns);

    SHA256_CTX sha_ctx;
    openssl_hash_init(&sha_ctx);
    for (int i=0; i<num_bns; i++) {
        const BIGNUM *bn = va_arg(vl, const BIGNUM*);
        openssl_hash_update_bignum(&sha_ctx, bn);
    }
    va_end(vl);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    openssl_hash_final(hash, &sha_ctx);
    BIGNUM *bn = openssl_hash2bignum(hash);
    return bn;
}

BIGNUM *openssl_hash_bn_list2bn(int num_bns, const BIGNUM *bn_list[]) {
    SHA256_CTX sha_ctx;
    openssl_hash_init(&sha_ctx);
    for (int i=0; i<num_bns; i++) {
        openssl_hash_update_bignum(&sha_ctx, bn_list[i]);
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    openssl_hash_final(hash, &sha_ctx);
    BIGNUM *bn = openssl_hash2bignum(hash);
    return bn;
}

BIGNUM *openssl_hash_point2bn(const EC_GROUP *group, BN_CTX *bn_ctx, const EC_POINT *point) {
    return openssl_hash_points2bn(group, bn_ctx, 1, point);
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

BIGNUM *openssl_hash_point_list2bn(const EC_GROUP *group, BN_CTX *bn_ctx, int list_len, const EC_POINT *point_list[]) {
    return openssl_hash_point_lists2bn(group, bn_ctx, 1, &list_len, &point_list);
}

BIGNUM *openssl_hash_point_lists2bn(const EC_GROUP *group, BN_CTX *bn_ctx, int num_lists, int *list_len, const EC_POINT **point_list[]) {
    SHA256_CTX sha_ctx;
    openssl_hash_init(&sha_ctx);
    for (int i=0; i<num_lists; i++) {
        const EC_POINT **pl = point_list[i];
        for (int j=0; j<list_len[i]; j++) {
            const EC_POINT *point = pl[j];
            openssl_hash_update_point(&sha_ctx, group, point, bn_ctx);
        }
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    openssl_hash_final(hash, &sha_ctx);
    BIGNUM *bn = openssl_hash2bignum(hash);
    return bn;
}

void openssl_hash_points2poly(const EC_GROUP *group, BN_CTX *ctx, int num_coeffs, BIGNUM *poly_coeff[], int num_point_lists, int *num_points, const EC_POINT ***point_list) {
    const BIGNUM *order = get0_order(group);

    assert(num_point_lists > 0 && "openssl_hash_points2poly: usage error, no point lists passed");
    BIGNUM *list_digest[num_point_lists];
    for (int i=0; i<num_point_lists; i++) {
        list_digest[i] = openssl_hash_point_list2bn(group, ctx, num_points[i], point_list[i]);
    }

    // hash chain coefficients
    poly_coeff[0] = openssl_hash_bn_list2bn(num_point_lists, (const BIGNUM**)list_digest);
    for (int i=1; i<num_coeffs; i++) {
        poly_coeff[i] = openssl_hash_bn2bn(poly_coeff[i-1]);
    }
    // reduce coefficients modulo group order
    // (not needed if group size is at most 2^{digest size in bits})
    for (int i=0; i<num_coeffs; i++) {
        BN_nnmod(poly_coeff[i], poly_coeff[i], order, ctx);
    }

    // cleanup
    for (int i=0; i<num_point_lists; i++) {
        bn_free(list_digest[i]);
    }
}
