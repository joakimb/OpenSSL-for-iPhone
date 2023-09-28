//
//  SSS.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-15.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#include "SSS.h"

void shamir_shares_generate(EC_POINT **shares, EC_POINT *secret, const int t, const int n) {
    const EC_GROUP *group = get0_group();
    const EC_POINT *generator = get0_generator(group);
    const BIGNUM *order = get0_order(group);

    BN_CTX *ctx = BN_CTX_new();
    //sample coefficients
    BIGNUM *coeffs[t+1];
    coeffs[0] = BN_new();
    BN_set_word(coeffs[0], 0);
    for (int i = 1; i < t + 1; i++){
        coeffs[i] = random_bignum(order, ctx);
    }
    
    BIGNUM *peval = BN_new();//space for evaluating polynomial
    BIGNUM *pterm = BN_new();//space for storing polynomial terms
    BIGNUM *base = BN_new();//space for storing polynomial terms
    BIGNUM *exp = BN_new();//space for storing polynomial terms
    //make shares for user i, counting starts from 1, not 0
    for (int i = 1; i <= n; i++){
        
        BN_set_word(peval, 0);//reset space for reuse
        
        //evaluate polynomial
        for (int j = 0; j < t + 1; j++) { //coeff * i ** j
            
            BN_set_word(base, i);
            BN_set_word(exp, j);
            BN_mod_exp(pterm, base, exp, order, ctx); // i**j
            BN_mod_mul(pterm, coeffs[j], pterm, order, ctx); //coeff * (i ** j)
            BN_mod_add(peval, peval, pterm, order, ctx); // add term to po;ly eval
            
        }
        
        shares[i - 1] = EC_POINT_new(group);//multiply(get0Gen(), peval);
        EC_POINT_mul(group, shares[i - 1], NULL, generator, peval, ctx);
        EC_POINT_add(group, shares[i - 1], shares[i - 1], secret, ctx);
    }
    
    for (int i = 0; i < t; i++){
        BN_free(coeffs[i]);
    }
    
    BN_free(peval);
    BN_free(pterm);
    BN_free(base);
    BN_free(exp);
    BN_CTX_free(ctx);
    
}

void lagX(BIGNUM *prod, int shareIndexes[], int length, int i, BN_CTX *ctx){
    const EC_GROUP *group = get0_group();
    const BIGNUM *order = get0_order(group);

    BIGNUM *numerator = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *denominator = BN_new();
    BIGNUM *fraction = BN_new();
    BN_set_word(prod, 1);
    
    for (int j = 0; j < length; j++) {
        if (i == j){
            continue;
        }
        BN_set_word(a, 0);
        BN_set_word(b, shareIndexes[j]);
        BN_sub(numerator, a,b);
        BN_set_word(a, shareIndexes[i]);
        BN_set_word(b, shareIndexes[j]);
        BN_sub(denominator, a, b);
        BN_mod_inverse(denominator, denominator, order, ctx);
        BN_mod_mul(fraction, numerator, denominator, order, ctx);
        BN_mod_mul(prod, prod, fraction, order, ctx);
    }
    BN_free(numerator);
    BN_free(a);
    BN_free(b);
    BN_free(denominator);
    BN_free(fraction);
}

EC_POINT *shamir_shares_reconstruct(EC_POINT *shares[], int shareIndexes[], int t, int length) {
    const EC_GROUP *group = get0_group();
    const EC_POINT *generator = get0_generator(group);

    if (length != t+1) {
        printf("bad number of shares for reconstructiong\n");
        return NULL;
    }
    
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM* zero = BN_new();
    EC_POINT *term = EC_POINT_new(group);
    BN_set_word(zero, 0);
    EC_POINT *sum = EC_POINT_new(group);
    EC_POINT_mul(group, sum, NULL, generator, zero, ctx);
    
    BIGNUM *lagrangeProd = BN_new();
    
    for (int i = 0; i < length; i++) {
        
        lagX(lagrangeProd, shareIndexes, length, i, ctx);
        EC_POINT_mul(group, term, NULL, shares[i], lagrangeProd, ctx);
        EC_POINT_add(group, sum, sum, term, ctx);
    }
    
    EC_POINT_free(term);
    BN_free(lagrangeProd);
    BN_free(zero);
    BN_CTX_free(ctx);
    return sum;
}

int test_shamir_sharing(void) {
    const EC_GROUP *group = get0_group();
    const EC_POINT *generator = get0_generator(group);

//    const int t = 1000; // t + 1 needed to reconstruct
//    const int n = 2000;
    const int t = 1; // t + 1 needed to reconstruct
    const int n = 3;
    EC_POINT *shares[n];
    
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *seven = BN_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = EC_POINT_new(group);
    EC_POINT_mul(group, secret, NULL, generator, seven, ctx);
    printf("secret:\n");
    print_point(group, secret, ctx);
    
    shamir_shares_generate(shares, secret, t, n);
#if 0
    printf("shares:\n");
    for (int i = 0; i < n; i++){
        printPoint(group, shares[i], ctx);
    }
#endif
    //reconstruct with 2nd and thrid share
    int shareIndexes[t+1];
    EC_POINT *recShares[t+1];
    for (int i = 0; i < t+1; i++) {
        shareIndexes[i] = i + 2;//user indexes 1 to t + 1
        recShares[i] = shares[i + 1];
        //printf("share %d on loc %d\n",i+2, i+1 );
    }
    EC_POINT *reconstructed = shamir_shares_reconstruct(recShares, shareIndexes, t, t + 1);

    int res = EC_POINT_cmp(group, secret, reconstructed, ctx);

    printf("reconstructed:\n");
    print_point(group, reconstructed, ctx);

    printf("Reconstruction %s\n", res ? "NOT OK" : "OK");

    BN_free(seven);
    EC_POINT_free(secret);
    EC_POINT_free(reconstructed);
    BN_CTX_free(ctx);
    
    return res;
}
