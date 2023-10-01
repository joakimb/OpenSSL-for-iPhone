//
//  P256.h

//  Created by Joakim Brorsson on 2023-09-05.//

#ifndef ShamirP256_h
#define ShamirP256_h


#endif /* ShamirP256_h */

#import <Foundation/Foundation.h>
#import "P256.h"
#import "SSS.h"
#import "nizk_dl.h"
#import "nizk_dl_eq.h"
#import "nizk_reshare.h"

@interface ShamirP256: NSObject

// debug helper to print bignums to terminal
+ (void) print: (BIGNUM *) x;

+ (NSString *)test:(NSString *) string;

@end
