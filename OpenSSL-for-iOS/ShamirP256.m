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

    BN_CTX *ctx = BN_CTX_new();
    
    //test curve multiplication
    const int numMultiplications = 10000;//*10000;
    const EC_POINT *gen = get0Gen();
    BIGNUM *rand = randZp();
    for (int i=0; i<numMultiplications; i++) {
        multiply(gen, rand);
    }
    BN_free(rand);
    BIGNUM *five = BN_new(), *six = BN_new(), *eleven = BN_new();
    BN_dec2bn(&five, "5");
    BN_dec2bn(&six, "6");
    BN_dec2bn(&eleven, "11");
    EC_POINT *pfive = multiply(gen, five);
    EC_POINT *psix = multiply(gen, six);
    EC_POINT *peleven = multiply(gen, eleven);
    EC_POINT *added = EC_POINT_new(getGroup());
    EC_POINT_add(getGroup(), added, psix, pfive, ctx);
    
    if(EC_POINT_cmp(getGroup(), peleven, added, ctx) == 0){
        printf("mul works as expected\n");
    } else {
        printf("mul NOT working as expected\n");
    }
    BN_free(five);
    BN_free(six);
    BN_free(eleven);
    EC_POINT_free(pfive);
    EC_POINT_free(psix);
    EC_POINT_free(peleven);
    EC_POINT_free(added);

    //test modp
    printf("modadd stuff \n");
    BIGNUM *a = BN_new(), *b = BN_new(), *c = BN_new(), *r = BN_new(), *tmp = BN_new();
    BN_dec2bn(&a, "3");
    BN_dec2bn(&b, "3");
    BN_dec2bn(&c, "5");
    
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
    BIGNUM *resm = BN_new(), *base = BN_new(), *exp = BN_new(), *mod = BN_new();
    BN_dec2bn(&base, "123");
    BN_dec2bn(&exp, "456");
    BN_dec2bn(&mod, "789");
    
    BN_CTX *ctx2 = BN_CTX_new();
    BN_mod_exp(resm, base, exp, mod, ctx2);
    printf("r (expected 699): \t\t:");
    printBN(resm);
    
    BN_free(resm);
    BN_free(base);
    BN_free(exp);
    BN_free(mod);
    BN_CTX_free(ctx2);
    
    //test modinv
    

    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    NSString *formattedString = [[NSString alloc] initWithFormat:@"Time: %f seconds\n", elapsed_time];
    NSLog(formattedString);

    return @"";
}


@end
