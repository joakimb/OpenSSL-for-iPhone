//
//  P256.m
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-05.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "P256.h"
#include <openssl/bn.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#import <openssl/evp.h>

@implementation P256

+ (NSString *)test:(NSString *)string {
    
    
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // Use the desired elliptic curve
    
    if (!ec_key) {
        printf("Error creating EC_KEY");
    }
    
    if (EC_KEY_generate_key(ec_key) != 1) {
        printf("Error generating EC key");
    }
    
    // Generate a random scalar as the private key
    BIGNUM *private_key = BN_new();
    if (!BN_rand(private_key, 256, -1, 0)) {
        printf("Error generating random private key");
    }
    
    // Print the private and public keys
    printf("Private Key: 0x%s\n", BN_bn2hex(private_key));
    
    clock_t start_time = clock();
    
    const numMultiplications = 10000;
    
    // Generate the corresponding public key (point multiplication)
    volatile EC_POINT *public_key = EC_POINT_new(EC_KEY_get0_group(ec_key));
    for (int i=0; i<numMultiplications; i++) {
        if (!EC_POINT_mul(EC_KEY_get0_group(ec_key), public_key, private_key, NULL, NULL, NULL)) {
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
    EC_KEY_free(ec_key);
    
    return formattedString;
}

@end
