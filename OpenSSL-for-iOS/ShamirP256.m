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
    printBN(x);
}

+ (NSString *)test:(NSString *) string {

    clock_t start_time = clock();

    //test getorder
    const BIGNUM *order = get0Order();
    printf("order:");
    printBN(order);

    //test get radom Zp element
    BIGNUM *randnum = randZp();
    printf("randint:");
    printBN(randnum);
    BN_free(randnum);

    //test curve multiplication
    const numMultiplications = 10000;//*10000;
    const EC_POINT *gen = get0Gen();
    BIGNUM *rand = randZp();
    for (int i=0; i<numMultiplications; i++) {
        multiply(gen, rand);
    }
    BN_free(rand);
   
    
    
    //test modp
    printf("modadd stuff \n");
    BIGNUM *a = BN_new(), *b = BN_new(), *c = BN_new(), *r = BN_new(), *tmp = BN_new();
    BN_dec2bn(&a, "3");
    BN_dec2bn(&b, "3");
    BN_dec2bn(&c, "5");
    BN_CTX *ctx = BN_CTX_new();
    
    BN_mod_add(r, a, b, c, ctx);
    printf("r (expected 1): \t\t:");
    printBN(r);
    
    
    BN_add(tmp, a, get0Order()); //3 + p
    BN_mod(r, tmp, get0Order(), ctx);// 3+p mod p
    printf("r (expected 3): \t\t:");
    printBN(r);
   
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_free(r);
    BN_free(tmp);
    BN_CTX_free(ctx);

    
    //testmodexp
    
    //test modinv
    //TODO
    
    //test pointadd
    //TODO

    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    NSString *formattedString = [[NSString alloc] initWithFormat:@"Time: %f seconds\n", elapsed_time];
    NSLog(formattedString);

    return @"";
}


@end
