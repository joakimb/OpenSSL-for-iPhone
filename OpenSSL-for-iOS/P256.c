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

const EC_GROUP* get0Group(void){
    
    if (debug){
    //use toy curve
        
        if (!group){
            // ----------- Custom group (toy curve EC29 for debugging) ---------
            BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new(), *x = BN_new(), *y = BN_new(), *order = BN_new(), *cofactor = BN_new();
            BN_dec2bn(&p, "29");
            BN_dec2bn(&a, "4");
            BN_dec2bn(&b, "20");
            BN_dec2bn(&x, "1");
            BN_dec2bn(&y, "5");
            BN_dec2bn(&order, "37");
            BN_dec2bn(&cofactor, "1");
            group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
            //// Set the generator point, order, and cofactor for the custom curve
            EC_POINT *generator = EC_POINT_new(group);
            EC_POINT_set_affine_coordinates_GFp(group, generator, x, y, NULL);
            EC_GROUP_set_generator(group, generator, order, cofactor);
            EC_POINT_free(generator);

        }
        
    } else {
        
        if (!group){
            group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        }
        
    }
   
    if (!group) {
        printf("Error getting group\n");
    }
    
    return group;
    
}

const BIGNUM* get0Order(void) {
        //using get0 means ownership is reteined by parent object
    const BIGNUM *order = EC_GROUP_get0_order(get0Group());
    if (order == NULL) {
        printf("Error getting group order\n");
    }
    return order;
}

const EC_POINT* get0Gen(void) {
        //using get0 means ownership is reteined by parent object
    const EC_POINT *gen = EC_GROUP_get0_generator(get0Group());
    if (gen == NULL) {
        printf("Error getting group order\n");
    }
    return gen;
}

const BIGNUM* get0OrderFromGroup(const EC_GROUP *group) {
        //using get0 means ownership is reteined by parent object
    const BIGNUM *order = EC_GROUP_get0_order(group);
    assert(order && "getOrderFromGroup: order not retrieved");
    return order;
}

const EC_POINT* get0GeneratorFromGroup(const EC_GROUP *group) {
        //using get0 means ownership is reteined by parent object
    const EC_POINT *generator = EC_GROUP_get0_generator(group);
    assert(generator && "get0GeneratorFromGroup: generator not retrieved");
    return generator;
}


void printBN(const BIGNUM *x) {
    char *num= BN_bn2dec(x);
    printf("%s\n", num);
    OPENSSL_free(num);
}

void printPoint(const EC_POINT *p, BN_CTX *ctx){
   
    //using uncompressed point format for printing
    
   //call with NULL to get buffer size needed
    size_t bufsize = EC_POINT_point2oct(get0Group(), p, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    unsigned char *buf = malloc(bufsize);
    EC_POINT_point2oct(get0Group(), p, POINT_CONVERSION_UNCOMPRESSED, buf, bufsize, ctx);
    
    printf("hex: (");
    for (size_t i = 1; i <= (bufsize - 1) / 2; i++) {
        printf("%02X", buf[i]);
    }
    printf(",\n      ");
    for (size_t i = (bufsize - 1) / 2 + 1; i < bufsize; i++) {
        printf("%02X", buf[i]);
    }
    printf(")\ndec: (");
        for (size_t i = 1; i <= (bufsize - 1) / 2; i++) {
        printf("%d", (int)buf[i]);
    }
    printf(",\n      ");
    for (size_t i = (bufsize - 1) / 2 + 1; i < bufsize; i++) {
        printf("%d", (int)buf[i]);
    }
    printf(")\n");

    free(buf);
}

BIGNUM* randZp(BN_CTX *ctx){
    
    BIGNUM *r = BN_new(); //init to zero
    
    
    if (!BN_rand(r, 256, -1, 0)) { // store a random value in it
        printf("Error generating random element in Zp\n");
    }

    if (debug){
        //eliminate randomness, all rands are five
        BN_set_word(r, 5);
    } else {
        BN_mod(r, r, get0Order(), ctx);
    }
    
    return r;
    
}

// get random point on curve
EC_POINT *randPoint(const EC_GROUP *group, BN_CTX *ctx) {
    BIGNUM *bn = randZp(ctx);
    EC_POINT *point = EC_POINT_new(group);
    EC_POINT_bn2point(group, bn, point, ctx);
    BN_free(bn);
    return point;
}

void point_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *bn, const EC_POINT *point, BN_CTX *ctx) {
    int ret = EC_POINT_mul(group, r, NULL, point, bn, ctx);
    if (ret != 1) {
        printf("\n*** point_mul ERROR 1 ***\n");
    }
    if (!BN_is_zero(bn) && EC_POINT_is_at_infinity(group, point)) {
        printf("\n*** point_mul ERROR 2 ***\n");
    }
    if (BN_is_zero(bn) && !EC_POINT_is_at_infinity(group, point)) {
        printf("\n*** point_mul ERROR 3 ***\n");
    }
}

EC_POINT* bn2point(const EC_GROUP *group, const BIGNUM *bn, BN_CTX *ctx) {
    EC_POINT *point = EC_POINT_new(group);
    int ret = EC_POINT_mul(group, point, bn, NULL, NULL, ctx);
    if (ret != 1) {
        printf("\n*** bn2point ERROR 1 ***\n");
    }
    if (!BN_is_zero(bn) && EC_POINT_is_at_infinity(group, point)) {
        printf("\n*** bn2point ERROR 2 ***\n");
    }
    if (BN_is_zero(bn) && !EC_POINT_is_at_infinity(group, point)) {
        printf("\n*** bn2point ERROR 3 ***\n");
    }
    return point;
}
