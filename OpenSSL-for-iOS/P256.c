//
//  P256.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-07.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

// ----------- Custom group ---------
// Define the curve parameters (replace these with your curve's parameters)
//const BIGNUM *p = ...;  // Prime field
//const BIGNUM *a = ...;  // Coefficient 'a'
//const BIGNUM *b = ...;  // Coefficient 'b'
//const BIGNUM *x = ...;  // x-coordinate of base point
//const BIGNUM *y = ...;  // y-coordinate of base point
//const BIGNUM *order = ...;  // Order of the base point
//const BIGNUM *cofactor = ...;  // Cofactor
//
//// Create an EC_GROUP object for the custom curve
//EC_GROUP *curve_group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
//
//if (curve_group == NULL) {
//    // Handle error
//    // ...
//}
//
//// Set the generator point, order, and cofactor for the custom curve
//EC_POINT *generator = EC_POINT_new(curve_group);
//EC_POINT_set_affine_coordinates_GFp(curve_group, generator, x, y, NULL);
//EC_GROUP_set_generator(curve_group, generator, order, cofactor);
//EC_POINT_free(generator);


#include "P256.h"


EC_GROUP* getGroup(void){
    
    static int initialized;
    static EC_GROUP *group; //
    
    if (!initialized){
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        initialized = 1;
    }
    
    if (group == NULL) {
        printf("Error getting group\n");
    }
    
    return group;
    
}

BIGNUM* get0Order(void) {
    
    //using get0 means ownership is reteined by parent object
    BIGNUM *order = EC_GROUP_get0_order(getGroup());
    
    if (order == NULL) {
        printf("Error getting group order\n");
    }
    
    return order;
}

EC_POINT* get0Gen(void) {
    
    //using get0 means ownership is reteined by parent object
    const EC_POINT *gen = EC_GROUP_get0_generator(getGroup());
    if (gen == NULL) {
        printf("Error getting group order\n");
    }
    
    return gen;
}

void print(const BIGNUM *x) {
    
    char *num= BN_bn2dec(x);
    printf("num: %s\n", num);
    OPENSSL_free(num);
    
}

BIGNUM* randZp(void){
    
    BIGNUM *r = BN_new(); //init to zero
    
    if (!BN_rand(r, 256, -1, 0)) { // store a random value in it
        printf("Error generating random element in Zp\n");
    }
    
    return r;
    
}

EC_POINT* multiply(const EC_POINT* point, const BIGNUM *x){
    
    EC_POINT *res = EC_POINT_new(getGroup());
    
    if(!EC_POINT_mul(getGroup(), res, x, point, NULL, NULL)){
        printf("Error during curve multiplication\n");
    }
    
    return res;
    
}

//BIGNUM* modp(const BIGNUM* x){
//    return NULL;
//}
