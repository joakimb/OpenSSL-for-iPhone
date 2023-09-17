//
//  SSS.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-15.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#include "SSS.h"

void genShamirShares(EC_POINT **shares, EC_POINT *secret, const int t, const int n) {
    
    BN_CTX *ctx = BN_CTX_new();
    //sample coefficients
    BIGNUM *coeffs[t+1];
    coeffs[0] = BN_new();
    BN_set_word(coeffs[0], 0);
    for (int i = 1; i < t + 1; i++){
        coeffs[i] = randZp(ctx);
    }
    
    //debug
    printf("coeffs:\n");
    for (int i = 0; i < t + 1; i++) {
        printBN(coeffs[i]);
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
            BN_mod_exp(pterm, base, exp, get0Order(), ctx); // i**j
            BN_mod_mul(pterm, coeffs[j], pterm, get0Order(), ctx); //coeff * (i ** j)
            BN_mod_add(peval, peval, pterm, get0Order(), ctx); // add term to po;ly eval
//            printf("adding term: \n");
//            printBN(coeffs[j]);
//            printf(" * ");
//            printBN(base);
//            printf(" ** ");
//            printBN(exp);
//            printf(" = ");
//            printBN(pterm);
            
        }
        
//        printf("decimal share: ");
//        printBN(peval);
//        printf("pointshare: ");
        shares[i - 1] = multiply(get0Gen(), peval);
        EC_POINT_add(get0Group(), shares[i - 1], shares[i - 1], secret, ctx);
//        printPoint(shares[i-1], ctx);
        
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
    BIGNUM *numerator = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *denominator = BN_new();
    BIGNUM *fraction = BN_new();
    BN_set_word(prod, 1);
    
    for (int j = 0; j < length; j++){
        
        if (i ==j){
            continue;
        }
        
        printf("i: %d, j: %d:\n",i,j);
        
//        int intNumerator = 0 - shareIndexes[j];
//        int intDenominator = shareIndexes[i] - shareIndexes[j];
//        printf("num: %d, den: %d\n",intNumerator,intDenominator);
        
        BN_set_word(a, 0);
        BN_set_word(b, shareIndexes[j]);
        BN_sub(numerator, a,b);
        BN_set_word(a, shareIndexes[i]);
        BN_set_word(b, shareIndexes[j]);
        BN_sub(denominator, a, b);
        //test to see if geeting rid of negative numbers resolves modinv issue:
        //BN_add(denominator, denominator, get0Order());
        printf("inv of ");
        printBN(denominator);
        printf("mod ");
        printBN(get0Order());
        printf("is");
        BN_mod_inverse(denominator, denominator, get0Order(), ctx);
        printBN(denominator);
        //ok, modinv behaves differently in the different libraries. might be sue to negative numbers?
        printBN(denominator);
        BN_mod_mul(fraction, numerator, denominator, get0Order(), ctx);
        BN_mod_mul(prod, prod, fraction, get0Order(), ctx);
        
    }
    
    BN_free(numerator);
    BN_free(a);
    BN_free(b);
    BN_free(denominator);
    BN_free(fraction);
    
}

EC_POINT* gShamirReconstruct(EC_POINT *shares[], int shareIndexes[], int t, int length) {
    
    if (length != t+1) {
        printf("bad number of shares for reconstructiong\n");
        return NULL;
    }
    
    BIGNUM* zero = BN_new();
    BN_set_word(zero, 0);
    EC_POINT *sum = multiply(get0Gen(), zero); //verify that this is correct after sleeping
    BN_free(zero);
    BN_CTX *ctx = BN_CTX_new();
    
    BIGNUM *lagrangeProd = BN_new();
    BIGNUM *term = BN_new();
    
    for (int i = 0; i < length; i++) {
        
        printf("reconstructing for share i = %d ",i);
        printPoint(shares[i], ctx);
        printf("shareindex: %d\n", shareIndexes[i]);
        lagX(lagrangeProd, shareIndexes, length, i, ctx);
        printf("lag: ");
        printBN(lagrangeProd);
        EC_POINT *term = multiply(shares[i], lagrangeProd);//consider refactor to make multiply take result as an input pointer, to allow reuse and avoid multiple allocations
        EC_POINT_add(get0Group(), sum, sum, term, ctx);
        EC_POINT_free(term);
    }
    
    BN_free(lagrangeProd);
    BN_free(term);
    BN_CTX_free(ctx);
    
    return sum;
    
}
