//
//  DH_PVSS.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-10-01.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#include "DH_PVSS.h"
#include <assert.h>

void DH_PVSS_params_free(DH_PVSS_params *pp) {
    //free bignums
    for (int i = 0; i < pp->n; i++) {
        BN_free(pp->alphas[i]);
        BN_free(pp->betas[i]);
        BN_free(pp->vs[i]);
        BN_free(pp->v_primes[i]);
    }
    BN_free(pp->alphas[pp->n]);
    BN_free(pp->betas[pp->n]);
    BN_free(pp->v_primes[pp->n]);
    
    //free arrays
    free(pp->alphas);
    free(pp->betas);
    free(pp->vs);
    free(pp->v_primes);
}

DH_PVSS_params *DH_PVSS_params_new(const int t, const int n){
    
    DH_PVSS_params *pp;
    // TODO: fix unallocated pp
    
    pp->t = t;
    pp->n = n;
    pp->alphas      = malloc(sizeof(BIGNUM *) * (n + 1));
    pp->betas       = malloc(sizeof(BIGNUM *) * (n + 1));
    pp->vs          = malloc(sizeof(BIGNUM *) * n);
    pp->v_primes    = malloc(sizeof(BIGNUM *) * (n + 1));
    
    //allocate BIGNUMS
    for (int i = 0; i < n; i++) {
        pp->alphas[i]   = BN_new();
        pp->betas[i]    = BN_new();
        pp->vs[i]       = BN_new();
        pp->v_primes[i] = BN_new();
    }
    pp->alphas[n]   = BN_new();
    pp->betas[n]    = BN_new();
    pp->v_primes[n] = BN_new();
        
    return pp;
    
}

void deriveScrapeCoeffs(BIGNUM **coeffs, int from, int n, BIGNUM **evaluationPoints, BN_CTX *ctx) {
    
    const BIGNUM *order = get0_order(get0_group());
    BIGNUM *term = BN_new();
    
    for (int i = 1; i <= n; i++) {
        
        BIGNUM *coeff = coeffs[i - 1];
        BN_set_word(coeff, 1);
        
        for (int j = from; j <= n; j++) {
            
            if (i == j) {
                continue;
            }
            
            BN_mod_sub(term, evaluationPoints[i], evaluationPoints[j], order, ctx);
            BN_mod_inverse(term, term, order, ctx);
            BN_mod_mul(coeff, coeff, term, order, ctx);
        }
    }
    BN_free(term);
}

DH_PVSS_params *setup(const int t, const int n, BN_CTX *ctx) {
    
    assert( (n - t - 2) > 0 && "n and t relation bad");
    
    DH_PVSS_params *pp = DH_PVSS_params_new(t, n);
    
    //fill alphas and betas
    for (int i = 0; i < n + 1; i++) {
        BN_set_word(pp->alphas[i], i);
        BN_set_word(pp->betas[i], i);
    }
    
    //fill vs and v_primes
    deriveScrapeCoeffs(pp->vs, 1, n, pp->alphas, ctx);
    deriveScrapeCoeffs(pp->v_primes, 0, n, pp->betas, ctx);
 
    return pp;
}

static int DH_PVSS_test_1(int print) {
    printf("PLACEHOLDER1\n");
    
    BN_CTX *ctx = BN_CTX_new();
    
    int t = 1;
    int n = 4;
    DH_PVSS_params *pp = setup(t, n, ctx);
    printf("alphas[3]: ");
    print_bn(pp->alphas[3]);
    
    DH_PVSS_params_free(pp);
    BN_CTX_free(ctx);
    
    // TODO: do a sharing, and verify proof
    
    return 0;// success
}

static int DH_PVSS_test_2(int print) {
    printf("PLACEHOLDER2\n");
    return 0;// success
}

typedef int (*test_function)(int);

static test_function test_suite[] = {
    &DH_PVSS_test_1,
    &DH_PVSS_test_2
};

// return test results
//   0 = passed (all individual tests passed)
//   1 = failed (one or more individual tests failed)
// setting print to 0 (zero) suppresses stdio printouts, while print 1 is 'verbose'
int DH_PVSS_test_suite(int print) {
    int num_tests = sizeof(test_suite)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite[i](print)) {
            ret = 1;
        }
    }
    return ret;
}
