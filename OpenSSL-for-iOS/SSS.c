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
