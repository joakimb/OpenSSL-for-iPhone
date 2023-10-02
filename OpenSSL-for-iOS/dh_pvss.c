//
//  dh_pvss.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-10-01.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#include "dh_pvss.h"
#include <assert.h>
#include "SSS.h"

void dh_pvss_ctx_free(dh_pvss_ctx *pp) {
    for (int i=0; i<pp->n+1; i++) {
        BN_free(pp->alphas[i]);
        BN_free(pp->betas[i]);
        BN_free(pp->v_primes[i]);
    }
    for (int i=0; i<pp->n; i++) {
        BN_free(pp->vs[i]);
    }
    free(pp->alphas);
    free(pp->betas);
    free(pp->v_primes);
    free(pp->vs);
}

void dh_key_pair_free(dh_key_pair *kp) {
    BN_free(kp->priv);
    EC_POINT_free(kp->pub);
    free(kp);
}

static void dh_pvss_ctx_init(dh_pvss_ctx *pp, const int t, const int n) {
    pp->t = t;
    pp->n = n;

    // allocate vectors
    pp->alphas   = malloc(sizeof(BIGNUM *) * (n + 1));
    pp->betas    = malloc(sizeof(BIGNUM *) * (n + 1));
    pp->v_primes = malloc(sizeof(BIGNUM *) * (n + 1));
    pp->vs       = malloc(sizeof(BIGNUM *) * n);
    assert(pp->alphas && "dh_pvss_ctx_init: allocation error alphas");
    assert(pp->betas && "dh_pvss_ctx_init: allocation error betas");
    assert(pp->v_primes && "dh_pvss_ctx_init: allocation error v_primes");
    assert(pp->vs && "dh_pvss_ctx_init: allocation error vs");

    // allocate vector entries
    for (int i=0; i<n+1; i++) {
        pp->alphas[i]   = BN_new();
        pp->betas[i]    = BN_new();
        pp->v_primes[i] = BN_new();
    }
    for (int i=0; i<n; i++) {
        pp->vs[i] = BN_new();
    }
}

static void deriveScrapeCoeffs(const EC_GROUP *group, BIGNUM **coeffs, int from, int n, BIGNUM **evaluationPoints, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);

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

void dh_pvss_setup(dh_pvss_ctx *pp, const EC_GROUP *group, const int t, const int n, BN_CTX *ctx) {
    assert( (n - t - 2) > 0 && "usage error, n and t badly chosen");

    dh_pvss_ctx_init(pp, t, n);

    // fill alphas and betas
    for (int i = 0; i < n + 1; i++) {
        BN_set_word(pp->alphas[i], i);
        BN_set_word(pp->betas[i], i);
    }

    //fill vs and v_primes
    deriveScrapeCoeffs(group, pp->vs, 1, n, pp->alphas, ctx);
    deriveScrapeCoeffs(group, pp->v_primes, 0, n, pp->betas, ctx);
}

void dh_key_gen(dh_key_pair *kp, BN_CTX *ctx) {
    
    const EC_GROUP *group = get0_group();
    const BIGNUM *order = get0_order(group);
    const EC_POINT *generator = get0_generator(group);
    kp->priv = bn_random(order, ctx);
    kp->pub = EC_POINT_new(group);
    point_mul(group, kp->pub, kp->priv, generator, ctx);
}

void dh_key_pair_prove(dh_key_pair *kp, nizk_dl_proof *pi, BN_CTX *ctx) {
    const EC_GROUP *group = get0_group();
    nizk_dl_prove(group, kp->priv, pi, ctx);
}

int dh_pub_key_verify(const EC_POINT *pubKey, const nizk_dl_proof *pi, BN_CTX *ctx) {
    
    const EC_GROUP *group = get0_group();
    return nizk_dl_verify(group, pubKey, pi, ctx);
}

void gen_scrape_sum_terms(BIGNUM** terms, BIGNUM **eval_points, BIGNUM** code_coeffs, BIGNUM** poly_coeffs, int n, int poly_coeffs_len, BN_CTX *ctx) {
    
    const BIGNUM *order = get0_order(get0_group());
    BIGNUM *poly_eval = BN_new();
    BIGNUM *poly_term = BN_new();
    BIGNUM *exp       = BN_new();
    
    for (int x = 1; x <= n; x++) {
        
        BIGNUM* eval_point = eval_points[x];
        BN_set_word(poly_eval, 0);
        
        for (int i = 0; i < poly_coeffs_len; i++) {
            
            BN_set_word(exp, i);
            BN_mod_exp(poly_term, eval_point, exp, order, ctx);
            BN_mod_mul(poly_term, poly_term, poly_coeffs[i], order, ctx);
            BN_mod_add(poly_eval, poly_eval, poly_term, order, ctx);
        }
        
        BN_mod_mul(terms[x - 1], code_coeffs[x - 1], poly_eval, order, ctx);
    }
    
    BN_free(poly_eval);
    BN_free(poly_term);
    BN_free(exp);
    
}



static void pvss_distribute(const EC_GROUP *group, EC_POINT **enc_shares, dh_pvss_ctx *pp, BIGNUM *priv_dist, EC_POINT **com_keys, EC_POINT *secret, BN_CTX *ctx) {

//    const EC_POINT *generator = get0_generator(group);
    
    EC_POINT *shares[pp->n];
    shamir_shares_generate(group, shares, secret, pp->t, pp->n, ctx);
    
    //encrypt shares
    for (int i = 0; i < pp->n; i++) {
        enc_shares[i] = EC_POINT_new(group);
        EC_POINT *enc_share = enc_shares[i];
        point_mul(group, enc_share, priv_dist, com_keys[i], ctx);
        point_add(group, enc_share, enc_share, shares[i], ctx);
    }
}

void prove_pvss_distribute(nizk_reshare_proof *pi, EC_POINT **enc_shares, dh_pvss_ctx *pp, BIGNUM *priv_dist, EC_POINT **com_keys, BN_CTX *ctx) {
    
//    const EC_GROUP *group = get0_group();
    
    //hash to poly coeffs
    int degree = pp->n - pp->t - 2;
    BIGNUM *poly_coeffs[degree + 1];
    // TODO: populate poly_coeffs
    
    BIGNUM *scrape_terms[pp->n];
    gen_scrape_sum_terms(scrape_terms, pp->alphas, pp->vs, poly_coeffs, pp->n, degree + 1, ctx);
    
//    EC_POINT *V = bn2point(group, <#const BIGNUM *bn#>, <#BN_CTX *ctx#>);
//    BIGNUM
//    EC_POINT *prod = EC_POINT_new(<#const EC_GROUP *group#>)
//    for (int i = 0; i < pp->n; i++) {
//
//    }
    
    // TODO: cleanup
    

}

static int dh_pvss_test_1(int print) {
    printf("PLACEHOLDER1\n");
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    
    int t = 1;
    int n = 4;
    dh_pvss_ctx pp;
    dh_pvss_setup(&pp, group, t, n, ctx);
    printf("alphas[3]: ");
    bn_print(pp.alphas[3]);
    
    dh_pvss_ctx_free(&pp);
    BN_CTX_free(ctx);
    
//    EC_POINT enc_shares[pp->n];
//    enc_shares = malloc(sizeof(EC_POINT *) * pp->n);
    
//    distribute_pvss(enc_shares, pp, BIGNUM *priv_dist, EC_POINT **com_keys, EC_POINT *secret, BN_CTX *ctx)
    
    // TODO: verify proof
    
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
