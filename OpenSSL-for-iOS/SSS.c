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
    BIGNUM *coeffs[t];
    for (int i = 0; i < t; i++){
        coeffs[i] = randZp(ctx);
        printBN(coeffs[i]);
    }
    
    BIGNUM *peval = BN_new();//space for evaluating polynomial
    BIGNUM *pterm = BN_new();//space for storing polynomial terms
    BIGNUM *base = BN_new();//space for storing polynomial terms
    BIGNUM *exp = BN_new();//space for storing polynomial terms
    //make shares for user i
    for (int i = 0; i < n; i++){
        
        
        //evaluate polynomial
        for (int j = 0; j < t; j++) { //coeff * i ** j
            
            BN_set_word(base, i);
            BN_set_word(exp, j);
            BN_mod_exp(pterm, base, exp, get0Order(), ctx); // i**j
            BN_mod_mul(pterm, coeffs[j], pterm, get0Order(), ctx); //coeff * (i ** j)
            BN_mod_add(peval, peval, pterm, get0Order(), ctx); // add term to po;ly eval
            
        }
        
        shares[i] = multiply(get0Gen(), peval);
        
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
    BIGNUM *denominator = BN_new();
    BIGNUM *fraction = BN_new();
    BN_set_word(prod, 1);
    
    for (int j = 0; j < length; j++){
        
        if (i ==j){
            continue;
        }
        
        int intNumerator = 0 - shareIndexes[j];
        int intDenominator = shareIndexes[i] - shareIndexes[j];
        BN_set_word(numerator, intNumerator);
        BN_set_word(denominator, intDenominator);
        BN_mod_inverse(denominator, denominator, get0Order(), ctx);
        BN_mod_mul(fraction, numerator, denominator, get0Order(), ctx);
        BN_mod_mul(prod, prod, fraction, get0Order(), ctx);
        
    }
    
    BN_free(numerator);
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
        
        lagX(lagrangeProd, shareIndexes, length, i, ctx);
        EC_POINT *term = multiply(shares[i], lagrangeProd);//consider refactor to make multiply take result as an input pointer, to allow reuse and avoid multiple allocations
        EC_POINT_add(get0Group(), sum, sum, term, ctx);
        EC_POINT_free(term);
    }
    
    BN_free(lagrangeProd);
    BN_free(term);
    BN_CTX_free(ctx);
    
    return sum;
    
}
