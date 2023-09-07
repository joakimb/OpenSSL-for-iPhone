//
//  P256.h

//  Created by Joakim Brorsson on 2023-09-05.//

#ifndef ShamirP256_h
#define ShamirP256_h


#endif /* ShamirP256_h */

#import <Foundation/Foundation.h>
#include <openssl/bn.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#import <openssl/evp.h>

@interface ShamirP256: NSObject

-(id) init;

// debug helper to print bignums to terminal
+ (void) print: (BIGNUM *) x;

+ (NSString *)test:(NSString *) string;

-(void) dealloc;

@end
