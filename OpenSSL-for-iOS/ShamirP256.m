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
    
    BN_free(seven);
    BN_CTX_free(ctx4);
    EC_POINT_free(secret);
    EC_POINT_free(reconstructed);
    
    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    NSString *formattedString = [[NSString alloc] initWithFormat:@"Time: %f seconds\n", elapsed_time];
    NSLog(formattedString);
    
    return @"";
}


@end
