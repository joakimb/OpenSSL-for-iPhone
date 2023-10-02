//
//  dh_pvss.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-10-01.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#include "dh_pvss.h"
#include <assert.h>

void dh_pvss_params_free(dh_pvss_params *pp) {
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
    
    //free struct
    free(pp);
}

void key_pair_free(key_pair *kp) {
    BN_free(kp->priv);
    EC_POINT_free(kp->pub);
    free(kp);
}

dh_pvss_params *dh_pvss_params_new(const int t, const int n){
    
    dh_pvss_params *pp = malloc(sizeof(dh_pvss_params));
    assert(pp && "error during pp allocation");
    
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

dh_pvss_params *setup(const int t, const int n, BN_CTX *ctx) {
    
    assert( (n - t - 2) > 0 && "n and t relation bad");
    
    dh_pvss_params *pp = dh_pvss_params_new(t, n);
    
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

void key_gen(key_pair *kp, BN_CTX *ctx) {
    
    const EC_GROUP *group = get0_group();
    const BIGNUM *order = get0_order(group);
    const EC_POINT *generator = get0_generator(group);
    kp->priv = random_bignum(order, ctx);
    kp->pub = EC_POINT_new(group);
    point_mul(group, kp->pub, kp->priv, generator, ctx);
}

void prove_key_pair(key_pair *kp, nizk_dl_proof *pi, BN_CTX *ctx) {
    const EC_GROUP *group = get0_group();
    nizk_dl_prove(group, kp->priv, pi, ctx);
}

int verify_pub_key(const EC_POINT *pubKey, const nizk_dl_proof *pi, BN_CTX *ctx) {
    
    const EC_GROUP *group = get0_group();
    return nizk_dl_verify(group, pubKey, pi, ctx);
}

static int dh_pvss_test_1(int print) {
    printf("PLACEHOLDER1\n");
    
    BN_CTX *ctx = BN_CTX_new();
    
    int t = 1;
    int n = 4;
    dh_pvss_params *pp = setup(t, n, ctx);
    printf("alphas[3]: ");
    print_bn(pp->alphas[3]);
    
    dh_pvss_params_free(pp);
    BN_CTX_free(ctx);
    
    // TODO: do a sharing, and verify proof
    
    return 0;// success
}

static int dh_pvss_test_2(int print) {
    printf("PLACEHOLDER2\n");
    return 0;// success
}

typedef int (*test_function)(int);

static test_function test_suite[] = {
    &dh_pvss_test_1,
    &dh_pvss_test_2
};

// return test results
//   0 = passed (all individual tests passed)
//   1 = failed (one or more individual tests failed)
// setting print to 0 (zero) suppresses stdio printouts, while print 1 is 'verbose'
int dh_pvss_test_suite(int print) {
    int num_tests = sizeof(test_suite)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite[i](print)) {
            ret = 1;
        }
    }
    return ret;
}
