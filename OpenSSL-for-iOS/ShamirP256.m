//
//  P256.m
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-05.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#import "ShamirP256.h"


@implementation ShamirP256

+ (void) print: (BIGNUM *) x {
    print(x);
}

+ (NSString *)test:(NSString *) string {

    clock_t start_time = clock();

    //test getorder
    const BIGNUM *order = get0Order();
    printf("order:");
    print(order);

    //test get radom Zp element
    BIGNUM *randnum = randZp();
    printf("randint:");
    print(randnum);
    BN_free(randnum);
    
    //test curve multiplication
    const numMultiplications = 10000;//*10000;
    const EC_POINT *gen = get0Gen();
    BIGNUM *r = randZp();

    for (int i=0; i<numMultiplications; i++) {
        multiply(gen, r);
    }
    BN_free(r);

    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    NSString *formattedString = [[NSString alloc] initWithFormat:@"Time: %f seconds\n", elapsed_time];
    NSLog(formattedString);

    return @"";
}


@end
