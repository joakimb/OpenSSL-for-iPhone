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

const int use_toy_curve = 0;
const int kill_randomness = 1;

static EC_GROUP *group = NULL;

const EC_GROUP *get0_group(void) {
    if (group) {
        return group;
    }

    // instantiate group
    if (use_toy_curve) { // use toy curve
        // ----------- Custom group (toy curve EC29 for debugging) ---------
        BIGNUM *p = bn_new();
        BIGNUM *a = bn_new();
        BIGNUM *b = bn_new();
        BIGNUM *x = bn_new();
        BIGNUM *y = bn_new();
        BIGNUM *order = bn_new();
        BIGNUM *cofactor = bn_new();
        BN_dec2bn(&p, "29");
        BN_dec2bn(&a, "4");
        BN_dec2bn(&b, "20");
        BN_dec2bn(&x, "1");
        BN_dec2bn(&y, "5");
        BN_dec2bn(&order, "37");
        BN_dec2bn(&cofactor, "1");
        group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
        // set generator point, order and cofactor for the custom curve
        EC_POINT *generator = point_new(group);
        EC_POINT_set_affine_coordinates_GFp(group, generator, x, y, NULL);
        EC_GROUP_set_generator(group, generator, order, cofactor);
        point_free(generator);
    } else {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    }
    assert(group && "get0Group: group not instantiated");
    return group;
}

BIGNUM *bn_new(void) {
    BIGNUM *bn = BN_new();
    assert(bn && "bn_new: allocation failed");
    return bn;
}

void bn_free(BIGNUM *bn) {
    BN_free(bn);
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

void bn_print(const BIGNUM *x) {
    char *num = BN_bn2dec(x);
    printf("%s", num);
    OPENSSL_free(num);
}

EC_POINT *point_new(const EC_GROUP *group) {
    EC_POINT *p = EC_POINT_new(group);
    assert(p && "point_new: allocation failed");
    return p;
}

void point_free(EC_POINT *a) {
    EC_POINT_free(a);
}

void point_print(const EC_GROUP *group, const EC_POINT *p, BN_CTX *ctx){
    BIGNUM *x = bn_new();
    BIGNUM *y = bn_new();
    if (EC_POINT_get_affine_coordinates_GFp(group, p, x, y, NULL)) {
        printf("(");
        bn_print(x);
        printf(", ");
        bn_print(y);
        printf(")");
    }
    bn_free(x);
    bn_free(y);
}

// random bignum (modulo group order)
BIGNUM* bn_random(const BIGNUM *modulus, BN_CTX *ctx) {
    BIGNUM *r = bn_new();
    assert(r && "random_bignum: no r generated");

    if (kill_randomness) { // eliminate randomness, all rands are five
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

// check for point equality
int point_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx) {
    int ret = EC_POINT_cmp(group, a, b, ctx);
    // EC_POINT_cmp returns 1 if the points are not equal, 0 if they are, or -1 on error.
    assert(ret != -1 && "nizk_dl_eq_verify: error in EC_POINT_cmp(Ra_prime, Ra)");
    return ret;
}

// get random point on curve
EC_POINT *point_random(const EC_GROUP *group, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);
    BIGNUM *bn = bn_random(order, ctx);
    EC_POINT *point = bn2point(group, bn, ctx);
    bn_free(bn);
    return point;
}

void point_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *bn, const EC_POINT *point, BN_CTX *ctx) {
    int ret = EC_POINT_mul(group, r, NULL, point, bn, ctx);
    assert(ret == 1 && "point_mul: EC_POINT_mul failed");
}

// r = sum_{0..n-1}(w_i * p[i])
void point_weighted_sum(const EC_GROUP *group, EC_POINT *r, int num_terms, const BIGNUM **w, const EC_POINT **p, BN_CTX *ctx) {
    assert(num_terms > 0 && "point_weighted_sum: usage error, unexpected parameter");
    point_mul(group, r, w[0], p[0], ctx);
    EC_POINT *t = point_new(group); // temp
    assert(t && "point_weighted_sum: usage error, unexpected parameter");
    for (int i=1; i<num_terms; i++) {
        point_mul(group, t, w[i], p[i], ctx);
        point_add(group, r, r, t, ctx);
    }

    // cleanup
    point_free(t);
}

void point_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx) {
    int ret = EC_POINT_add(group, r, a, b, ctx);
    assert(ret == 1 && "point_add: EC_POINT_add failed");
}

void point_sub(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx) {
    EC_POINT *b_copy = EC_POINT_dup(b, group);
    assert(b_copy && "point_sub: point duplication failed");
    int ret = EC_POINT_invert(group, b_copy, ctx); // invert b_copy instead of b to avoid side effects on input parameter
    assert(ret == 1 && "point_sub: EC_POINT_invert failed");
    ret = EC_POINT_add(group, r, a, b_copy, ctx);
    assert(ret == 1 && "point_sub: EC_POINT_add failed");
    point_free(b_copy);
}

// convert bignum to point
EC_POINT *bn2point(const EC_GROUP *group, const BIGNUM *bn, BN_CTX *ctx) {
    EC_POINT *point = point_new(group);
    assert(point && "bn2point: no point allocated");
    int ret = EC_POINT_mul(group, point, bn, NULL, NULL, ctx);
    assert(ret == 1 && "bn2point: EC_POINT_mul failed");
    return point;
}
