//
//  P256.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-07.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//


#include "P256.h"
#include <string.h>

static EC_GROUP *group = NULL;

EC_GROUP* get0Group(void){
    
    int toyCurve = 1;
    
    if (toyCurve){
        
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

EC_POINT* get0Gen(void) {
    
    //using get0 means ownership is reteined by parent object
    const EC_POINT *gen = EC_GROUP_get0_generator(get0Group());
    if (gen == NULL) {
        printf("Error getting group order\n");
    }
    
    return gen;
}

void printBN(const BIGNUM *x) {
    
    char *num= BN_bn2dec(x);
    printf("%s\n", num);
    OPENSSL_free(num);
    
}

//BIGNUM* intToBN(int x){
//    
//    BIGNUM *bn = BN_new();
//    if(!BN_set_word(bn, x)){
//        printf("Error setting bignum");
//    }
//    
//    return bn;
//    
//}


BIGNUM* randZp(BN_CTX *ctx){
    
    BIGNUM *r = BN_new(); //init to zero
    
    if (!BN_rand(r, 256, -1, 0)) { // store a random value in it
        printf("Error generating random element in Zp\n");
    }
    
    BN_mod(r, r, get0Order(), ctx);
    
    return r;
    
}

EC_POINT* multiply(const EC_POINT* point, const BIGNUM *x){
    
    EC_POINT *res = EC_POINT_new(get0Group());
    
    if(!EC_POINT_mul(get0Group(), res, NULL, point, x, NULL)){
//    if(!EC_POINT_mul(getGroup(), res, x, point, NULL, NULL)){
        printf("Error during curve multiplication\n");
    }
    
    return res;
    
}

EC_POINT* add(const EC_POINT* a, const EC_POINT* b){
    
    EC_POINT *res = EC_POINT_new(get0Group());
    
    if (!EC_POINT_add(get0Group(), res, a, b, NULL)){
        printf("Error during curve addition\n");
    }
    
    return res;
}
