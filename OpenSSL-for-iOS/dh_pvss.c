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
#include "openssl_hashing_tools.h"

/* dh key pair utilities */

void dh_key_pair_free(dh_key_pair *kp) {
    BN_free(kp->priv);
    EC_POINT_free(kp->pub);
}

void dh_key_pair_generate(const EC_GROUP *group, dh_key_pair *kp, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);
    kp->priv = bn_random(order, ctx);
    kp->pub = bn2point(group, kp->priv, ctx);
}

void dh_key_pair_prove(const EC_GROUP *group, dh_key_pair *kp, nizk_dl_proof *pi, BN_CTX *ctx) {
    nizk_dl_prove(group, kp->priv, pi, ctx);
}

int dh_pub_key_verify(const EC_GROUP *group, const EC_POINT *pub_key, const nizk_dl_proof *pi, BN_CTX *ctx) {
    return nizk_dl_verify(group, pub_key, pi, ctx);
}

/* dhpvss */

void dh_pvss_ctx_free(dh_pvss_ctx *pp) {
    // free entries
    for (int i=0; i<pp->n+1; i++) {
        BN_free(pp->alphas[i]);
        BN_free(pp->betas[i]);
        BN_free(pp->v_primes[i]);
    }
    for (int i=0; i<pp->n; i++) {
        BN_free(pp->vs[i]);
    }
    // free arrays
    free(pp->alphas);
    free(pp->betas);
    free(pp->v_primes);
    free(pp->vs);
}

static void derive_scrape_coeffs(const EC_GROUP *group, BIGNUM **coeffs, int from, int n, BIGNUM **evaluationPoints, BN_CTX *ctx) {
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
        assert(pp->alphas[i] && "dh_pvss_ctx_init: allocation error for entry in alphas");
        pp->betas[i]    = BN_new();
        assert(pp->betas[i] && "dh_pvss_ctx_init: allocation error for entry in betas");
        pp->v_primes[i] = BN_new();
        assert(pp->v_primes[i] && "dh_pvss_ctx_init: allocation error for entry in v_primes");
    }
    for (int i=0; i<n; i++) {
        pp->vs[i] = BN_new();
        assert(pp->vs[i] && "dh_pvss_ctx_init: allocation error for entry in vs");
    }

    // fill alphas and betas
    for (int i=0; i<n+1; i++) {
        BN_set_word(pp->alphas[i], i);
        BN_set_word(pp->betas[i], i);
    }

    // fill vs and v_primes
    derive_scrape_coeffs(group, pp->vs, 1, n, pp->alphas, ctx);
    derive_scrape_coeffs(group, pp->v_primes, 0, n, pp->betas, ctx);
}

static void generate_scrape_sum_terms(const EC_GROUP *group, BIGNUM** terms, BIGNUM **eval_points, BIGNUM** code_coeffs, BIGNUM **poly_coeff, int n, int num_poly_coeffs, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);

    BIGNUM *poly_eval = BN_new();
    BIGNUM *poly_term = BN_new();
    BIGNUM *exp       = BN_new();
    for (int x=1; x<=n; x++) {
        BIGNUM *eval_point = eval_points[x];
        BN_set_word(poly_eval, 0);
        for (int i=0; i<num_poly_coeffs; i++) {
            BN_set_word(exp, i);
            BN_mod_exp(poly_term, eval_point, exp, order, ctx);
            BN_mod_mul(poly_term, poly_term, poly_coeff[i], order, ctx);
            BN_mod_add(poly_eval, poly_eval, poly_term, order, ctx);
        }
        terms[x - 1] = BN_new();
        BN_mod_mul(terms[x - 1], code_coeffs[x - 1], poly_eval, order, ctx);
    }

    // cleanup
    BN_free(poly_eval);
    BN_free(poly_term);
    BN_free(exp);
}

void dh_pvss_distribute_prove(const EC_GROUP *group, EC_POINT **enc_shares, dh_pvss_ctx *pp, dh_key_pair *dist_key, const EC_POINT *com_keys[], EC_POINT *secret, nizk_dl_eq_proof *pi, BN_CTX *ctx) {
    const int n = pp->n;
    const int t = pp->t;

    // create shares
    EC_POINT *shares[n]; // share container
    shamir_shares_generate(group, shares, secret, t, n, ctx); // shares allocated here

    // encrypt shares
    for (int i=0; i<n; i++) {
        EC_POINT *enc_share = enc_shares[i] = EC_POINT_new(group);
        point_mul(group, enc_share, dist_key->priv, com_keys[i], ctx);
        point_add(group, enc_share, enc_share, shares[i], ctx);
    }

    // degree n-t-2 polynomial = hash(dist_key->pub, com_keys)
    const int num_poly_coeffs = n - t - 2;
    BIGNUM *poly_coeffs[num_poly_coeffs]; // polynomial container
    
    openssl_hash_points2poly(group, ctx, num_poly_coeffs, poly_coeffs, dist_key->pub, n, com_keys, (const EC_POINT**)enc_shares);

    // generate scrape sum terms
    BIGNUM *scrape_terms[n];
    generate_scrape_sum_terms(group, scrape_terms, pp->alphas, pp->vs, poly_coeffs, n, num_poly_coeffs, ctx);

    // compute U and V
    EC_POINT *U = EC_POINT_new(group);
    EC_POINT *V = EC_POINT_new(group);
//    EC_POINT_set_to_infinity(group, U); //set to zero
//    EC_POINT_set_to_infinity(group, V); //set to zero

    // TODO: EC_POINTs_mul is deprecated, make a for loop with addition instead

    EC_POINTs_mul(group, U, NULL, n, com_keys, scrape_terms, ctx);
    EC_POINTs_mul(group, V, NULL, n, enc_shares, scrape_terms, ctx);

    // generate dl eq proof
    const EC_POINT *generator = get0_generator(group);
    nizk_dl_eq_prove(group, dist_key->priv, generator, dist_key->pub, U, V, pi, ctx);

    // cleanup
    EC_POINT_free(U);
    EC_POINT_free(V);
    for (int i=0; i<n; i++) {
        BN_free(scrape_terms[i]);
        EC_POINT_free(shares[i]);
    }
    for (int i=0; i<n-t-2; i++) {
        BN_free(poly_coeffs[i]);
    }
    
    // implicitly return (pi, enc_shares)
}

int dh_pvss_distribute_verify(const EC_GROUP *group, nizk_reshare_proof *pi, const EC_POINT **enc_shares, dh_pvss_ctx *pp, const EC_POINT *pub_dist, const EC_POINT **com_keys, BN_CTX *ctx) {
    const EC_POINT *generator = get0_generator(group);
    const int n = pp->n;
    const int t = pp->t;

    // degree n-t-2 polynomial = hash(dist_key->pub, com_keys)
    const int num_poly_coeffs = n - t - 2;
    BIGNUM *poly_coeffs[num_poly_coeffs]; // polynomial container
    
    openssl_hash_points2poly(group, ctx, num_poly_coeffs, poly_coeffs, pub_dist, n, com_keys, (const EC_POINT**)enc_shares);

    // generate scrape sum terms
    BIGNUM *scrape_terms[n];
    generate_scrape_sum_terms(group, scrape_terms, pp->alphas, pp->vs, poly_coeffs, n, num_poly_coeffs, ctx);

    // compute U and V
    EC_POINT *U = EC_POINT_new(group);
    EC_POINT *V = EC_POINT_new(group);
//    EC_POINT_set_to_infinity(group, U); //set to zero
//    EC_POINT_set_to_infinity(group, V); //set to zero

    // TODO: EC_POINTs_mul is deprecated, make a for loop with addition instead

    EC_POINTs_mul(group, U, NULL, n, com_keys, scrape_terms, ctx);
    EC_POINTs_mul(group, V, NULL, n, enc_shares, scrape_terms, ctx);
    // verify dl eq proof
    int ret = nizk_dl_eq_verify(group, generator, pub_dist, U, V, pi, ctx);

    // cleanup
    EC_POINT_free(U);
    EC_POINT_free(V);
    for (int i=0; i<n; i++) {
        BN_free(scrape_terms[i]);
    }
    for (int i=0; i<n-t-2; i++) {
        BN_free(poly_coeffs[i]);
    }

    return ret;
}

static int dh_pvss_test_1(int print) {
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();

    // setup
    
    int t = 1;
    int n = 4;
    dh_pvss_ctx pp;
    dh_pvss_setup(&pp, group, t, n, ctx);
    EC_POINT *secret = point_random(group, ctx);
    
    // keygen
    dh_key_pair first_dist_kp;
    dh_key_pair_generate(group, &first_dist_kp, ctx);
    dh_key_pair committee_key_pairs[pp.n];
    EC_POINT *committee_public_keys[pp.n];
    for (int i = 0; i<pp.n; i++) {
        dh_key_pair *com_member_key_pair = &committee_key_pairs[i];
        dh_key_pair_generate(group, com_member_key_pair, ctx);
        committee_public_keys[i] = com_member_key_pair->pub;
    }
    
    // make encrypted shares
    EC_POINT *enc_shares[pp.n];
    nizk_dl_eq_proof pi;
    dh_pvss_distribute_prove(group, enc_shares, &pp, &first_dist_kp, committee_public_keys, secret, &pi, ctx);
    
    int ret1 = dh_pvss_distribute_verify(group, &pi, enc_shares, &pp, first_dist_kp.pub, committee_public_keys, ctx);
    if (print) {
        printf("Test 4 part 1 %s: Correct dh_pvss_distribution Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // cleanup
    // TODO: make sure everything is cleaned up
    dh_pvss_ctx_free(&pp);
    BN_CTX_free(ctx);

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
