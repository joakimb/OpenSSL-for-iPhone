//
//  P256.h
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-07.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#ifndef P256_H
#define P256_H
#include <openssl/bn.h>
#include <openssl/ec.h>
#import <openssl/evp.h>

// get curve group
const EC_GROUP* get0_group(void);

// get curve group order
const BIGNUM* get0_order(const EC_GROUP *group);

// get curve group generator
const EC_POINT* get0_generator(const EC_GROUP *group);

/* BIGNUM functions, wrappers for OPENSSL BN_xxx functionality */

// get new bignum
BIGNUM *bn_new(void);

// free
void bn_free(BIGNUM *bn);

// get vector of new bignums
BIGNUM **bn_new_array(int len);

// free bn array
void bn_free_array(int len, BIGNUM **bn_array);

// get random element in Zp
BIGNUM *bn_random(const BIGNUM *modulus, BN_CTX *ctx);

// return bignum as point on curve (generator^bignum)
EC_POINT* bn2point(const EC_GROUP *group, const BIGNUM *bn, BN_CTX *ctx);

// helper to print bignum to terminal
void bn_print(const BIGNUM *x);


/* point functions, wrappers for OPENSSL EC_POINT_xxx functionality */

EC_POINT *point_new(const EC_GROUP *group);

void point_free(EC_POINT *a);

// check for point equality
int point_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);

// get random point on curve
EC_POINT *point_random(const EC_GROUP *group, BN_CTX *ctx);

// r = bn * point
void point_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *bn, const EC_POINT *point, BN_CTX *ctx);

// r = sum_{0..n-1}(w_i * p[i])
void point_weighted_sum(const EC_GROUP *group, EC_POINT *r, int num_terms, const BIGNUM **w, const EC_POINT **p, BN_CTX *ctx);

// r = a + b
void point_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);

// r = a - b
void point_sub(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);

// helper to print point to terminal
void point_print(const EC_GROUP *group, const EC_POINT *p, BN_CTX *ctx);

#endif /* P256_H */
