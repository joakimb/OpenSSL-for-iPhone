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
    
    BN_CTX *ctx = BN_CTX_new();
    
    //test getorder
    const BIGNUM *order = get0Order();
    printf("order:");
    printBN(order);
    
    //test get radom Zp element
    BIGNUM *randnum = randZp(ctx);
    printf("randint:");
    printBN(randnum);
    BN_free(randnum);
    
    
    //test curve multiplication
    const int numMultiplications = 10000;//*10000;
    const EC_POINT *gen = get0Gen();
    BIGNUM *rand = randZp(ctx);
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
    EC_POINT *added = EC_POINT_new(get0Group());
    EC_POINT_add(get0Group(), added, psix, pfive, ctx);
    
    if(EC_POINT_cmp(get0Group(), peleven, added, ctx) == 0){
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
    //    BN_dec2bn(&a, "3");
    //    BN_dec2bn(&b, "3");
    //    BN_dec2bn(&c, "5");
    BN_set_word(a, 3);
    BN_set_word(b, 3);
    BN_set_word(c, 5);
    
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
    BIGNUM *resi = BN_new(), *v = BN_new(), *w = BN_new();
    
    BN_dec2bn(&v, "456");
    BN_dec2bn(&w, "11");
    
    BN_CTX *ctx3 = BN_CTX_new();
    BN_mod_inverse(resi, v, w, ctx3);//returns NULL if inversese foes not exist
    printf("r (expected 9): \t\t:");
    printBN(resi);
    
    BN_CTX_free(ctx3);
    BN_free(resi);
    BN_free(v);
    BN_free(w);
    
    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    NSString *formattedString = [[NSString alloc] initWithFormat:@"Time: %f seconds\n", elapsed_time];
    NSLog(formattedString);
    
    //test gen shares
    const int t = 1; // t + 1 needed to reconstruct
    const int n = 3;
    EC_POINT *shares[n];
    
    BN_CTX *ctx4 = BN_CTX_new();
    BIGNUM *seven = BN_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = multiply(get0Gen(), seven);
    printf("secret: \n");
    printPoint(secret, ctx4);
    
    
    genShamirShares(shares, secret, t, n);
    
    printf("shares: \n");
    for (int i = 0; i < n; i++){
        printPoint(shares[i],ctx4);
    }
    
    //reconstruct with 2nd and thrid share
    int shareIndexes[t+1];
    EC_POINT *recShares[t+1];
    for (int i = 0; i < t+1; i++) {
        shareIndexes[i] = i + 2;//user indexes 1 to t + 1
        recShares[i] = shares[i + 1];
        printf("share %d on loc %d\n",i+2, i+1 );
    }
    EC_POINT *reconstructed = gShamirReconstruct(recShares, shareIndexes, t, t + 1);
    
    printf("reconstructed: ");
    printPoint(reconstructed, ctx4);
        
    //AFTER LUNCH, TEST toPoint in both languages and see if differs. Seems fine
//    for (int i = 1; i <= 40; i++) {
//        BIGNUM *bn = BN_new();
//        BN_set_word(bn, i);
//        EC_POINT *poi = multiply(get0Gen(), bn);
//        printf("%d : ",i);
//        printPoint(poi, ctx4);
//        BN_free(bn);
//        EC_POINT_free(poi);
//
//    }
        
    BN_free(seven);
    BN_CTX_free(ctx4);
    EC_POINT_free(secret);
    EC_POINT_free(reconstructed);
    return @"";
}


@end
