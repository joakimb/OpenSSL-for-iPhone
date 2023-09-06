//
//  P256.h

//  Created by Joakim Brorsson on 2023-09-05.//

#ifndef P256_h
#define P256_h


#endif /* P256_h */

#import <Foundation/Foundation.h>
#include <openssl/bn.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#import <openssl/evp.h>

@interface P256: NSObject

-(id) init;
-(void) dealloc;

// debug helper to print bignums to terminal
+ (void) print: (BIGNUM *) x;

// get curve order p (returns NULL on error)
- (const BIGNUM *) get0Order;

// get rand int < p

+ (NSString *)test:(NSString *)string;

@end
