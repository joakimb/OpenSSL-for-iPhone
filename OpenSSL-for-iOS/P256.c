//
//  P256.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-07.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//


#include <string.h>
#include <assert.h>
#include "P256.h"

const int debug = 0;

static EC_GROUP *group = NULL;

const EC_GROUP *get0_group(void) {
    if (group) {
        return group;
    }

    // instantiate group
    if (debug) { // use toy curve
        // ----------- Custom group (toy curve EC29 for debugging) ---------
        BIGNUM *p = BN_new();
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        BIGNUM *order = BN_new();
        BIGNUM *cofactor = BN_new();
        BN_dec2bn(&p, "29");
        BN_dec2bn(&a, "4");
        BN_dec2bn(&b, "20");
        BN_dec2bn(&x, "1");
        BN_dec2bn(&y, "5");
        BN_dec2bn(&order, "37");
        BN_dec2bn(&cofactor, "1");
        group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
        // set generator point, order and cofactor for the custom curve
        EC_POINT *generator = EC_POINT_new(group);
        EC_POINT_set_affine_coordinates_GFp(group, generator, x, y, NULL);
        EC_GROUP_set_generator(group, generator, order, cofactor);
        EC_POINT_free(generator);
    } else {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    }
    assert(group && "get0Group: group not instantiated");
    return group;
}

const BIGNUM* get0_order(const EC_GROUP *group) {
    // using get0 means ownership is reteined by parent object
    const BIGNUM *order = EC_GROUP_get0_order(group);
    assert(order && "getOrderFromGroup: order not retrieved");
    return order;
}

const EC_POINT* get0_generator(const EC_GROUP *group) {
    // using get0 means ownership is reteined by parent object
    const EC_POINT *generator = EC_GROUP_get0_generator(group);
    assert(generator && "get0GeneratorFromGroup: generator not retrieved");
    return generator;
}

void print_bn(const BIGNUM *x) {
    char *num = BN_bn2dec(x);
    printf("%s\n", num);
    OPENSSL_free(num);
}

void print_point(const EC_GROUP *group, const EC_POINT *p, BN_CTX *ctx){

    // using uncompressed point format for printing

    // call with NULL to get buffer size needed
    assert(group && "print_point: usage error, no group");
    assert(p && "print_point: usage error, no point");
    assert(ctx && "print_point: usage error, no ctx");
    size_t bufsize = EC_POINT_point2oct(group, p, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    unsigned char *buf = malloc(bufsize);
    assert(buf && "print_point: allocation error");
    EC_POINT_point2oct(group, p, POINT_CONVERSION_UNCOMPRESSED, buf, bufsize, ctx);

    // print point coordinates in hex
    printf("(");
    for (size_t i = 0; i <= (bufsize - 1) / 2; i++) {
        printf("%02X", buf[i]);
    }
    printf(", ");
    for (size_t i = (bufsize - 1) / 2 + 1; i < bufsize; i++) {
        printf("%02X", buf[i]);
    }
    printf(")");
#if 0
    // print point coordinates in dec
    printf("(");
        for (size_t i = 0; i <= (bufsize - 1) / 2; i++) {
        printf("%d", (int)buf[i]);
    }
    printf(",\n ");
    for (size_t i = (bufsize - 1) / 2 + 1; i < bufsize; i++) {
        printf("%d", (int)buf[i]);
    }
    printf(")\n");
#endif
    free(buf);
}

// random bignum (modulo group order)
BIGNUM* random_bignum(const BIGNUM *modulus, BN_CTX *ctx) {
    BIGNUM *r = BN_new();
    assert(r && "random_bignum: no r generated");

    if (debug) { // eliminate randomness, all rands are five
        int ret = BN_set_word(r, 5);
        assert(ret == 1 && "random_bignum: BN_set_word error");
        return r;
    }

    // set to uniformly random value
    int ret = BN_rand(r, 256, -1, 0); // store a random value in it
    assert(ret == 1 && "random_bignum: BN_rand error");
    ret = BN_mod(r, r, modulus, ctx);
    assert(ret == 1 && "random_bignum: BN_mod error");
    return r;
}

// get random point on curve
EC_POINT *random_point(const EC_GROUP *group, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);
    BIGNUM *bn = random_bignum(order, ctx);
    EC_POINT *point = bn2point(group, bn, ctx);
    BN_free(bn);
    return point;
}

void point_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *bn, const EC_POINT *point, BN_CTX *ctx) {
    int ret = EC_POINT_mul(group, r, NULL, point, bn, ctx);
    assert(ret == 1 && "point_mul: EC_POINT_mul failed");
}

// convert bignum to point
EC_POINT *bn2point(const EC_GROUP *group, const BIGNUM *bn, BN_CTX *ctx) {
    EC_POINT *point = EC_POINT_new(group);
    assert(point && "bn2point: no point allocated");
    int ret = EC_POINT_mul(group, point, bn, NULL, NULL, ctx);
    assert(ret == 1 && "bn2point: EC_POINT_mul failed");
    return point;
}
