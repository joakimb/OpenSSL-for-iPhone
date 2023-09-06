//
//  P256.m
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-05.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#import "P256.h"


@implementation P256

// How to print bignum
//    char *num= BN_bn2dec(order);
//    printf("num: %s\n", num);
//    OPENSSL_free(num);

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


EC_GROUP *group;

- (id) init {
    
    //P256
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    
    return self;
}

- (void) dealloc {
    
    EC_GROUP_free(group);
    
    //[super dealloc]; should not be called, ARC will insert it at build time
}

- (const BIGNUM *) get0Order {
    
    //using get0 means ownership is retained by parent object
    return EC_GROUP_get0_order(group);
    
}

+ (void) print: (BIGNUM *) x {
    char *num= BN_bn2dec(x);
    printf("num: %s\n", num);
    OPENSSL_free(num);
}

// mod p

// modular inverse of int

// get generator

// multiply Point with int < p

// add points

//

+ (NSString *)test:(NSString *)string {
    
    EC_GROUP *curve_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    
    if (curve_group == NULL) {
        // Handle error
    }
    
    //using get0 means ownership is reteined by parent object
    const BIGNUM *order = EC_GROUP_get0_order(curve_group);
    
    if (order == NULL) {
        // Handle error
    }
    
    // Generate a random scalar as the private key
    BIGNUM *private_key = BN_new(); //init to zero
    if (!BN_rand(private_key, 256, -1, 0)) { // store a random value in it
        printf("Error generating random private key");
    }
    
    // Print the private and public keys
    printf("Private Key: 0x%s\n", BN_bn2hex(private_key));
    
    clock_t start_time = clock();
    
    const numMultiplications = 10000;//*10000;
    
    // Generate the corresponding public key (point multiplication)
    volatile EC_POINT *public_key = EC_POINT_new(curve_group);
    for (int i=0; i<numMultiplications; i++) {
        if (!EC_POINT_mul(curve_group, public_key, private_key, NULL, NULL, NULL)) {
            printf("Error performing point multiplication");
        }
    }
    
    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    
    NSString *formattedString = [[NSString alloc] initWithFormat:@"Time for %d point multiplication: %6.3f seconds\nTime per multiplication: %27.12f seconds\n", numMultiplications, elapsed_time,  elapsed_time / numMultiplications];
    NSLog(formattedString);
    
    // Cleanup
    BN_free(private_key);
    EC_POINT_free(public_key);
    //EC_KEY_free(ec_key);
    EC_GROUP_free(curve_group);
    
    return formattedString;
}

@end
