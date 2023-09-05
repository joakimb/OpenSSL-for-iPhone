//
//  FSOpenSSL.m
//  OpenSSL-for-iOS
//
//  Created by Felix Schulze on 16.03.2013.
//  Copyright 2013 Felix Schulze. All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#import "FSOpenSSL.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#import <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <time.h>

@implementation FSOpenSSL

+ (NSString *)md5FromString:(NSString *)string {
    unsigned char *inStrg = (unsigned char *) [[string dataUsingEncoding:NSASCIIStringEncoding] bytes];
    unsigned long lngth = [string length];
    unsigned char result[MD5_DIGEST_LENGTH];
    NSMutableString *outStrg = [NSMutableString string];
    
    MD5(inStrg, lngth, result);
    
    unsigned int i;
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        [outStrg appendFormat:@"%02x", result[i]];
    }
    return [outStrg copy];
}

+ (NSString *)sha256FromString:(NSString *)string {
    unsigned char *inStrg = (unsigned char *) [[string dataUsingEncoding:NSASCIIStringEncoding] bytes];
    unsigned long lngth = [string length];
    unsigned char result[SHA256_DIGEST_LENGTH];
    NSMutableString *outStrg = [NSMutableString string];
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, inStrg, lngth);
    SHA256_Final(result, &sha256);
    
    unsigned int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        [outStrg appendFormat:@"%02x", result[i]];
    }
    return [outStrg copy];
}

+ (NSString *)sha512FromString:(NSString *)string {
    unsigned char *inStrg = (unsigned char *) [[string dataUsingEncoding:NSASCIIStringEncoding] bytes];
    unsigned long lngth = [string length];
    unsigned char result[SHA512_DIGEST_LENGTH];
    NSMutableString *outStrg = [NSMutableString string];
    
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, inStrg, lngth);
    SHA512_Final(result, &sha512);
    
    unsigned int i;
    for (i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        [outStrg appendFormat:@"%02x", result[i]];
    }
    return [outStrg copy];
}

+ (NSString *)base64FromString:(NSString *)string encodeWithNewlines:(BOOL)encodeWithNewlines {
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    
    if (!encodeWithNewlines) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    mem = BIO_push(b64, mem);
    
    NSData *stringData = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger length = stringData.length;
    void *buffer = (void *) [stringData bytes];
    int bufferSize = (int)MIN(length, INT_MAX);
    
    NSUInteger count = 0;
    
    BOOL error = NO;
    
    // Encode the data
    while (!error && count < length) {
        int result = BIO_write(mem, buffer, bufferSize);
        if (result <= 0) {
            error = YES;
        }
        else {
            count += result;
            buffer = (void *) [stringData bytes] + count;
            bufferSize = (int)MIN((length - count), INT_MAX);
        }
    }
    
    int flush_result = BIO_flush(mem);
    if (flush_result != 1) {
        return nil;
    }
    
    char *base64Pointer;
    NSUInteger base64Length = (NSUInteger) BIO_get_mem_data(mem, &base64Pointer);
    
    NSData *base64data = [NSData dataWithBytesNoCopy:base64Pointer length:base64Length freeWhenDone:NO];
    NSString *base64String = [[NSString alloc] initWithData:base64data encoding:NSUTF8StringEncoding];
    
    BIO_free_all(mem);
    return base64String;
}

+ (NSString *)test:(NSString *)string {
    
    
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1); // Use the desired elliptic curve
    
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
    
    printf("Time for %d point multiplication: %6.3f seconds\n", numMultiplications, elapsed_time);
    printf("Time per multiplication: %27.12f seconds\n", elapsed_time / numMultiplications);

    
    // Print the private and public keys
    printf("Private Key: 0x%s\n", BN_bn2hex(private_key));
    
    char *public_key_hex = EC_POINT_point2hex(EC_KEY_get0_group(ec_key), public_key, POINT_CONVERSION_COMPRESSED, NULL);
    printf("Public Key: %s\n", public_key_hex);
    
    // Cleanup
    BN_free(private_key);
    EC_POINT_free(public_key);
    EC_KEY_free(ec_key);
    OPENSSL_free(public_key_hex);
    
    return string;
}

@end
