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

void dh_pvss_ctx_free(dh_pvss_ctx *pp) {
    bn_free_array(pp->n+1, pp->alphas);
    bn_free_array(pp->n+1, pp->betas);
    bn_free_array(pp->n+1, pp->v_primes);
    bn_free_array(pp->n, pp->vs);
}

static void derive_scrape_coeffs(const EC_GROUP *group, BIGNUM **coeffs, int from, int n, BIGNUM **evaluationPoints, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);

    BIGNUM *term = bn_new();
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
    bn_free(term);
}

void dh_pvss_setup(dh_pvss_ctx *pp, const EC_GROUP *group, const int t, const int n, BN_CTX *bn_ctx) {
    assert(group && "dh_pvss_setup: usage error, no group specified");
    pp->group = group;
    assert(bn_ctx && "dh_pvss_setup: usage error, no BIGNUM context specified");
    pp->bn_ctx = bn_ctx;
    assert( (n - t - 2) > 0 && "dh_pvss_setup: usage error, n and t badly chosen");
    pp->t = t;
    pp->n = n;
    
    // allocate vectors
    pp->alphas   = bn_new_array(n+1);
    pp->betas    = bn_new_array(n+1);
    pp->v_primes = bn_new_array(n+1);
    pp->vs       = bn_new_array(n);

    // fill alphas and betas
    for (int i=0; i<n+1; i++) {
        BN_set_word(pp->alphas[i], i);
        BN_set_word(pp->betas[i], i);
    }

    // fill vs and v_primes
    derive_scrape_coeffs(group, pp->vs, 1, n, pp->alphas, bn_ctx);
    derive_scrape_coeffs(group, pp->v_primes, 0, n, pp->betas, bn_ctx);
}

static void generate_scrape_sum_terms(const EC_GROUP *group, BIGNUM** terms, BIGNUM **eval_points, BIGNUM** code_coeffs, BIGNUM **poly_coeff, int n, int num_poly_coeffs, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);
    
    BIGNUM *poly_eval = bn_new();
    BIGNUM *poly_term = bn_new();
    BIGNUM *exp       = bn_new();
    for (int x=1; x<=n; x++) {
        BIGNUM *eval_point = eval_points[x];
        BN_set_word(poly_eval, 0);
        for (int i=0; i<num_poly_coeffs; i++) {
            BN_set_word(exp, i);
            BN_mod_exp(poly_term, eval_point, exp, order, ctx);
            BN_mod_mul(poly_term, poly_term, poly_coeff[i], order, ctx);
            BN_mod_add(poly_eval, poly_eval, poly_term, order, ctx);
        }
        terms[x - 1] = bn_new();
        BN_mod_mul(terms[x - 1], code_coeffs[x - 1], poly_eval, order, ctx);
    }
    
    // cleanup
    bn_free(poly_eval);
    bn_free(poly_term);
    bn_free(exp);
}

void dh_pvss_distribute_prove(dh_pvss_ctx *pp, EC_POINT **encrypted_shares, dh_key_pair *dist_key, const EC_POINT *com_keys[], EC_POINT *secret, nizk_dl_eq_proof *pi) {
    const EC_GROUP *group = pp->group;
    BN_CTX *ctx = pp->bn_ctx;
    const int n = pp->n;
    const int t = pp->t;
    
    // create shares
    EC_POINT *shares[n]; // share container
    shamir_shares_generate(group, shares, secret, t, n, ctx); // shares allocated here
    
    // encrypt shares
    for (int i=0; i<n; i++) {
        EC_POINT *encrypted_share = encrypted_shares[i] = point_new(group);
        point_mul(group, encrypted_share, dist_key->priv, com_keys[i], ctx);
        point_add(group, encrypted_share, encrypted_share, shares[i], ctx);
    }
    
    // degree n-t-2 polynomial = hash(dist_key->pub, com_keys)
    const int num_poly_coeffs = n - t - 1;
    BIGNUM *poly_coeffs[num_poly_coeffs]; // polynomial container
    const int num_point_lists = 3;
    int num_points[num_point_lists] = {1, n, n};
    const EC_POINT **point_lists[num_point_lists] = { (const EC_POINT **)&(dist_key->pub), com_keys, (const EC_POINT **)encrypted_shares};
    openssl_hash_points2poly(group, ctx, num_poly_coeffs, poly_coeffs, num_point_lists, num_points, point_lists);
    
    // generate scrape sum terms
    BIGNUM *scrape_terms[n];
    generate_scrape_sum_terms(group, scrape_terms, pp->alphas, pp->vs, poly_coeffs, n, num_poly_coeffs, ctx);
    
    // compute U and V
    EC_POINT *U = point_new(group);
    EC_POINT *V = point_new(group);
    point_weighted_sum(group, U, n, (const BIGNUM**)scrape_terms, com_keys, ctx);
    point_weighted_sum(group, V, n, (const BIGNUM**)scrape_terms, (const EC_POINT**)encrypted_shares, ctx);
    
    // generate dl eq proof
    const EC_POINT *generator = get0_generator(group);
    nizk_dl_eq_prove(group, dist_key->priv, generator, dist_key->pub, U, V, pi, ctx);
    
    // cleanup
    point_free(U);
    point_free(V);
    for (int i=0; i<n; i++) {
        bn_free(scrape_terms[i]);
        point_free(shares[i]);
    }
    for (int i=0; i<num_poly_coeffs; i++) {
        bn_free(poly_coeffs[i]);
    }
    
    // implicitly return (pi, encrypted_shares)
}

int dh_pvss_distribute_verify(dh_pvss_ctx *pp, nizk_dl_eq_proof *pi, const EC_POINT **encrypted_shares, const EC_POINT *pub_dist, const EC_POINT **com_keys) {
    const EC_GROUP *group = pp->group;
    BN_CTX *ctx = pp->bn_ctx;
    const EC_POINT *generator = get0_generator(group);
    const int n = pp->n;
    const int t = pp->t;
    
    // degree n-t-2 polynomial <- hash(dist_key->pub, com_keys)
    const int num_poly_coeffs = n - t - 1;
    BIGNUM *poly_coeffs[num_poly_coeffs]; // polynomial container
    const int num_point_lists = 3;
    int num_points[num_point_lists] = {1, n, n};
    const EC_POINT **point_lists[num_point_lists] = { &(pub_dist), com_keys, (const EC_POINT **)encrypted_shares};
    openssl_hash_points2poly(group, ctx, num_poly_coeffs, poly_coeffs, num_point_lists, num_points, point_lists);
    
    // generate scrape sum terms
    BIGNUM *scrape_terms[n];
    generate_scrape_sum_terms(group, scrape_terms, pp->alphas, pp->vs, poly_coeffs, n, num_poly_coeffs, ctx);
    
    // compute U and V
    EC_POINT *U = point_new(group);
    EC_POINT *V = point_new(group);
    point_weighted_sum(group, U, n, (const BIGNUM**)scrape_terms, com_keys, ctx);
    point_weighted_sum(group, V, n, (const BIGNUM**)scrape_terms, encrypted_shares, ctx);
    
    // verify dl eq proof
    int ret = nizk_dl_eq_verify(group, generator, pub_dist, U, V, pi, ctx);
    
    // cleanup
    point_free(U);
    point_free(V);
    for (int i=0; i<n; i++) {
        bn_free(scrape_terms[i]);
    }
    for (int i=0; i<num_poly_coeffs; i++) {
        bn_free(poly_coeffs[i]);
    }
    
    return ret;
}

EC_POINT *dh_pvss_decrypt_share_prove(const EC_GROUP *group, const EC_POINT *dist_key_pub, dh_key_pair *C, const EC_POINT *encrypted_share, nizk_dl_eq_proof *pi, BN_CTX *ctx) {
    const EC_POINT *generator = get0_generator(group);
    
    // compute shared key
    EC_POINT *shared_key = point_new(group);
    point_mul(group, shared_key, C->priv, dist_key_pub, ctx);
    
    // decrypt share
    EC_POINT *decrypted_share = point_new(group);
    point_sub(group, decrypted_share, encrypted_share, shared_key, ctx);
    
    // compute difference
    EC_POINT *diff = point_new(group);
    point_sub(group, diff, encrypted_share, decrypted_share, ctx);
    
    // prove correct decryption
    nizk_dl_eq_prove(group, C->priv, generator, C->pub, dist_key_pub, diff, pi, ctx);
    
    // cleanup
    point_free(diff);
    point_free(shared_key);
    
    return decrypted_share; // return decrypted share and (implicitly) proof
}

int dh_pvss_decrypt_share_verify(const EC_GROUP *group, const EC_POINT *dist_key_pub, const EC_POINT *C_pub, const EC_POINT *encrypted_share, const EC_POINT *decrypted_share, nizk_dl_eq_proof *pi, BN_CTX *ctx) {
    const EC_POINT *generator = get0_generator(group);
    
    // compute difference
    EC_POINT *diff = point_new(group);
    point_sub(group, diff, encrypted_share, decrypted_share, ctx);
    
    // prove correct decryption
    int ret = nizk_dl_eq_verify(group, generator, C_pub, dist_key_pub, diff, pi, ctx);
    
    // cleanup
    point_free(diff);
    
    return ret; // return proof verification result
}

EC_POINT *dh_pvss_reconstruct(const EC_GROUP *group, const EC_POINT *shares[], int share_indices[], int t, int length, BN_CTX *ctx){
    // decrypted shares are plain shamir shares, so we just call shamir reconstruct
    return shamir_shares_reconstruct(group, shares, share_indices, t, length, ctx);
}

EC_POINT *dh_pvss_committee_dist_key_calc(const EC_GROUP *group, const EC_POINT *keys[], int key_indices[], int t, int length, BN_CTX *ctx) {
    // the implementation of this is identical to shamir reconstruct, so we call shamir reconstuct, but with keys instead of shares
    return shamir_shares_reconstruct(group, keys, key_indices, t, length, ctx);
}

void dh_pvss_reshare_prove(const EC_GROUP *group, int party_index, const dh_key_pair *party_committee_kp, const dh_key_pair *party_dist_kp, const EC_POINT *previous_dist_key, const EC_POINT *current_enc_shares[], const int current_n, const dh_pvss_ctx *next_pp, const EC_POINT *next_committee_keys[], EC_POINT *enc_re_shares[], nizk_reshare_proof *pi, BN_CTX *ctx) {
    const EC_POINT *generator = get0_generator(group);
    
    // compute shared key
    EC_POINT *shared_key = point_new(group);
    assert(shared_key && "dh_pvss_reshare_prove: allocation error for shared_key");
    point_mul(group, shared_key, party_committee_kp->priv, previous_dist_key, ctx);
    
    // decrypt share
    EC_POINT *decrypted_share = point_new(group);
    assert(decrypted_share && "dh_pvss_reshare_prove: allocation error for decrypted_share");
    point_sub(group, decrypted_share, current_enc_shares[party_index], shared_key, ctx);
    
    // create shares of it for next epoch committe
    EC_POINT *re_shares[next_pp->n];
    shamir_shares_generate(group, re_shares, decrypted_share, next_pp->t, next_pp->n, ctx);
    
    // encrypt the re_shares for the next epoch committee public keys
    EC_POINT *enc_shared_key = point_new(group);
    assert(enc_shared_key && "dh_pvss_reshare_prove: allocation error for enc_shared_key");
    for (int i = 0; i<next_pp->n; i++) {
        point_mul(group, enc_shared_key, party_dist_kp->priv, next_committee_keys[i], ctx);
        enc_re_shares[i] = point_new(group);
        point_add(group, enc_re_shares[i], enc_shared_key, re_shares[i], ctx);
    }
    
    // degree n-t-1 polynomial <- hash(previous_dist_key, current_enc_shares)
    const int num_poly_coeffs = next_pp->n - next_pp->t;
    BIGNUM *poly_coeffs[num_poly_coeffs]; // polynomial container
    const int num_point_lists = 2;
    int num_points[num_point_lists] = {1, current_n};
    const EC_POINT **point_lists[num_point_lists] = { &(previous_dist_key), current_enc_shares };
    openssl_hash_points2poly(group, ctx, num_poly_coeffs, poly_coeffs, num_point_lists, num_points, point_lists);
    
    // generate scrape sum terms
    BIGNUM *scrape_terms[next_pp->n];
    generate_scrape_sum_terms(group, scrape_terms, next_pp->betas, next_pp->v_primes, poly_coeffs, next_pp->n, num_poly_coeffs, ctx);
    
    // compute U', V' and W'
    EC_POINT *enc_re_share_diffs[next_pp->n];
    for (int i=0; i<next_pp->n; i++) {
        enc_re_share_diffs[i] = point_new(group);
        point_sub(group, enc_re_share_diffs[i], enc_re_shares[i], current_enc_shares[party_index], ctx);
    }
    EC_POINT *U_prime = point_new(group);
    EC_POINT *V_prime = point_new(group);
    EC_POINT *W_prime = point_new(group);
    
    point_weighted_sum(group, U_prime, next_pp->n, (const BIGNUM**)scrape_terms, (const EC_POINT**)enc_re_share_diffs, ctx);
    point_weighted_sum(group, V_prime, next_pp->n, (const BIGNUM**)scrape_terms, next_committee_keys, ctx);
    BIGNUM *W_sum = bn_new();
    for (int i=0; i<next_pp->n; i++) {
        BN_add(W_sum, W_sum, scrape_terms[i]);
    }
    point_mul(group, W_prime, W_sum, previous_dist_key, ctx);
    
    // prove correctness
    nizk_reshare_prove(group, party_committee_kp->priv, party_dist_kp->priv, generator, V_prime, W_prime, party_committee_kp->pub, party_dist_kp->pub, U_prime, pi, ctx);
    
    // cleanup
    for (int i=0; i<num_poly_coeffs; i++) {
        bn_free(poly_coeffs[i]);
    }
    for (int i=0; i<next_pp->n; i++) {
        point_free(re_shares[i]);
        bn_free(scrape_terms[i]);
        point_free(enc_re_share_diffs[i]);
    }
    point_free(enc_shared_key);
    point_free(U_prime);
    point_free(V_prime);
    bn_free(W_sum);
    point_free(W_prime);
}

int dh_pvss_reshare_verify(const dh_pvss_ctx *pp, const dh_pvss_ctx *next_pp, int party_index, const EC_POINT *party_committee_pub_key, const EC_POINT *party_dist_pub_key, const EC_POINT *previous_dist_key, const EC_POINT *current_enc_shares[], const EC_POINT *next_committee_keys[], EC_POINT *enc_re_shares[], nizk_reshare_proof *pi) {
    const EC_GROUP *group = pp->group; // TODO: use next group where appropriate
    const EC_POINT *generator = get0_generator(group);
    BN_CTX *ctx = pp->bn_ctx; // TODO: use next bn_ctx where appropriate
    const int current_n = pp->n;
    
    // degree n-t-1 polynomial <- hash(previous_dist_key, current_enc_shares)
    const int num_poly_coeffs = next_pp->n - next_pp->t;
    BIGNUM *poly_coeffs[num_poly_coeffs]; // polynomial container
    const int num_point_lists = 2;
    int num_points[num_point_lists] = {1, current_n};
    const EC_POINT **point_lists[num_point_lists] = { &(previous_dist_key), current_enc_shares };
    openssl_hash_points2poly(group, ctx, num_poly_coeffs, poly_coeffs, num_point_lists, num_points, point_lists);
    
    // generate scrape sum terms
    BIGNUM *scrape_terms[next_pp->n];
    generate_scrape_sum_terms(group, scrape_terms, next_pp->betas, next_pp->v_primes, poly_coeffs, next_pp->n, num_poly_coeffs, ctx);
    
    // compute U', V' and W'
    EC_POINT *enc_re_share_diffs[next_pp->n];
    for (int i=0; i<next_pp->n; i++) {
        enc_re_share_diffs[i] = point_new(group);
        point_sub(group, enc_re_share_diffs[i], enc_re_shares[i], current_enc_shares[party_index], ctx);
    }
    EC_POINT *U_prime = point_new(group);
    EC_POINT *V_prime = point_new(group);
    EC_POINT *W_prime = point_new(group);
    
    point_weighted_sum(group, U_prime, next_pp->n, (const BIGNUM**)scrape_terms, (const EC_POINT**)enc_re_share_diffs, ctx);
    point_weighted_sum(group, V_prime, next_pp->n, (const BIGNUM**)scrape_terms, next_committee_keys, ctx);
    BIGNUM *W_sum = bn_new();
    for (int i=0; i<next_pp->n; i++) {
        BN_add(W_sum, W_sum, scrape_terms[i]);
    }
    point_mul(group, W_prime, W_sum, previous_dist_key, ctx);
    
    // verify correctness
    int ret = nizk_reshare_verify(group, generator, V_prime, W_prime, party_committee_pub_key, party_dist_pub_key, U_prime, pi, ctx);
    
    // cleanup
    for (int i=0; i<num_poly_coeffs; i++) {
        bn_free(poly_coeffs[i]);
    }
    for (int i=0; i<next_pp->n; i++) {
        bn_free(scrape_terms[i]);
        point_free(enc_re_share_diffs[i]);
    }
    point_free(U_prime);
    point_free(V_prime);
    bn_free(W_sum);
    point_free(W_prime);
    
    return ret;
}

EC_POINT *dh_pvss_reconstruct_reshare(const dh_pvss_ctx *pp, int num_valid_indices, int *valid_indices, EC_POINT *enc_re_shares[]) {
    const EC_GROUP *group = pp->group;
    const BIGNUM *order = get0_order(group);
    BN_CTX *ctx = pp->bn_ctx;
    const int t = pp->t;
    
    // TODO: expect corresponding entries in enc_re_shares only

    if (num_valid_indices != t + 1) {
        return NULL; // reconstruction not possible
    }
    
    EC_POINT *sum = point_new(group);
    BIGNUM *lambda = bn_new();
    EC_POINT *lambC = point_new(group);
    for (int i=0; i<t+1; i++) {
        lagX(group, lambda, valid_indices, t+1, i, ctx);
        
        printf("lambda: ");
        bn_print(lambda);
        printf("\n");

        
        BN_nnmod(lambda, lambda, order, ctx);
        point_mul(group, lambC, lambda, enc_re_shares[i], ctx);
//        point_mul(group, lambC, lambda, enc_re_shares[valid_indices[i]], ctx);
        point_add(group, sum, sum, lambC, ctx);
    }
    
    // cleanup
    bn_free(lambda);
    point_free(lambC);
    
    return sum;
}

static int dh_pvss_test_1(int print) {
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    
    // setup
    int t = 50;
    int n = 100;
    dh_pvss_ctx pp;
    dh_pvss_setup(&pp, group, t, n, ctx);
    EC_POINT *secret = point_random(group, ctx);
    
    // keygen
    dh_key_pair first_dist_kp;
    dh_key_pair_generate(group, &first_dist_kp, ctx);
    dh_key_pair committee_key_pairs[n];
    EC_POINT *committee_public_keys[n];
    for (int i=0; i<n; i++) {
        dh_key_pair *com_member_key_pair = &committee_key_pairs[i];
        dh_key_pair_generate(group, com_member_key_pair, ctx);
        committee_public_keys[i] = com_member_key_pair->pub;
    }
    
    // make encrypted shares
    EC_POINT *enc_shares[n];
    nizk_dl_eq_proof pi;
    dh_pvss_distribute_prove(&pp, enc_shares, &first_dist_kp, (const EC_POINT**)committee_public_keys, secret, &pi);
    
    // positive test
    int ret1 = dh_pvss_distribute_verify(&pp, &pi, (const EC_POINT**)enc_shares, first_dist_kp.pub, (const EC_POINT**)committee_public_keys);
    if (print) {
        printf("%6s Test 1: Correct DH PVSS Distribution Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }
    
    // cleanup
    BN_CTX_free(ctx);
    dh_pvss_ctx_free(&pp);
    point_free(secret);
    dh_key_pair_free(&first_dist_kp);
    for (int i=0; i<n; i++){
        dh_key_pair_free(&committee_key_pairs[i]);
        point_free(enc_shares[i]);
    }
    nizk_dl_eq_proof_free(&pi);
    
    // return test results
    return ret1 != 0;
}

static int dh_pvss_test_2(int print) {
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    
    // setup
    const int t = 50;
    const int n = 100;
    dh_pvss_ctx pp;
    dh_pvss_setup(&pp, group, t, n, ctx);
    EC_POINT *secret = point_random(group, ctx);
    
    // keygen
    dh_key_pair first_dist_kp;
    dh_key_pair_generate(group, &first_dist_kp, ctx);
    dh_key_pair committee_key_pairs[n];
    EC_POINT *committee_public_keys[n];
    for (int i=0; i<n; i++) {
        dh_key_pair *com_member_key_pair = &committee_key_pairs[i];
        dh_key_pair_generate(group, com_member_key_pair, ctx);
        committee_public_keys[i] = com_member_key_pair->pub;
    }
    
    // make encrypted shares
    EC_POINT *enc_shares[pp.n];
    nizk_dl_eq_proof pi;
    dh_pvss_distribute_prove(&pp, enc_shares, &first_dist_kp, (const EC_POINT**)committee_public_keys, secret, &pi);
    
    // positive test
    int ret1 = dh_pvss_distribute_verify(&pp, &pi, (const EC_POINT**)enc_shares, first_dist_kp.pub, (const EC_POINT**)committee_public_keys);
    if (print) {
        printf("%6s Test 2 - 1: Correct DH PVSS Distribution Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }
    
    //negative test
    int ret2 = dh_pvss_distribute_verify(&pp, &pi, (const EC_POINT**)enc_shares, committee_public_keys[0], (const EC_POINT**)committee_public_keys);
    if (print) {
        if (ret2) {
            printf("    OK Test 2 - 2: Incorrect NIZK DL Proof not accepted (which is CORRECT)\n");
        } else {
            printf("NOT OK Test 2 - 2: Incorrect NIZK DL Proof IS accepted (which is an ERROR)\n");
        }
    }
    
    // cleanup
    BN_CTX_free(ctx);
    dh_pvss_ctx_free(&pp);
    point_free(secret);
    dh_key_pair_free(&first_dist_kp);
    for (int i=0; i<n; i++){
        dh_key_pair_free(&committee_key_pairs[i]);
        point_free(enc_shares[i]);
    }
    nizk_dl_eq_proof_free(&pi);
    
    return !(ret1 == 0 && ret2 != 0);// success
}

static int dh_pvss_test_3(int print) {
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    
    // setup
    const int t = 50;
    const int n = 100;
    dh_pvss_ctx pp;
    dh_pvss_setup(&pp, group, t, n, ctx);
    EC_POINT *secret = point_random(group, ctx);
    
    // keygen
    dh_key_pair first_dist_kp;
    dh_key_pair_generate(group, &first_dist_kp, ctx);
    dh_key_pair committee_key_pairs[n];
    EC_POINT *committee_public_keys[n];
    for (int i=0; i<n; i++) {
        dh_key_pair *com_member_key_pair = &committee_key_pairs[i];
        dh_key_pair_generate(group, com_member_key_pair, ctx);
        committee_public_keys[i] = com_member_key_pair->pub;
    }

    // make encrypted shares with proof
    EC_POINT *encrypted_shares[n];
    nizk_dl_eq_proof distribution_pi;
    dh_pvss_distribute_prove(&pp, encrypted_shares, &first_dist_kp, (const EC_POINT**)committee_public_keys, secret, &distribution_pi);
    
    // verify encrypted shares
    int ret1 = dh_pvss_distribute_verify(&pp, &distribution_pi, (const EC_POINT**)encrypted_shares, first_dist_kp.pub, (const EC_POINT**)committee_public_keys);
    if (print) {
        printf("%6s Test 3 - 1: Correct DH PVSS Distribution Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }
    
    // decrypting the encrypted shares and verifiying
    EC_POINT *decrypted_shares[n];
    int num_failed_decryptions = 0;
    int num_failed_verifications = 0;
    for (int i=0; i<n; i++) {
        nizk_dl_eq_proof committee_member_pi;
        decrypted_shares[i] = dh_pvss_decrypt_share_prove(group, first_dist_kp.pub, &committee_key_pairs[i], encrypted_shares[i], &committee_member_pi, ctx);
        if (decrypted_shares[i] == NULL) {
            num_failed_decryptions++;
            if (print) {
                printf("failed to decrypt an encrypted share\n");
            }
            continue; // decryption failed, so skip verification test
        }
        int ret2 = dh_pvss_decrypt_share_verify(group, first_dist_kp.pub, committee_public_keys[i], encrypted_shares[i], decrypted_shares[i], &committee_member_pi, ctx);
        if (ret2) {
            num_failed_verifications++;
            if (print) {
                printf("failed to verify a decrypted share\n");
            }
        }
        
        // cleanup
        nizk_dl_eq_proof_free(&committee_member_pi);
    }
    if (print) {
        if (num_failed_decryptions == 0 && num_failed_verifications == 0) {
            printf("    OK Test 3 - 2: all encrypted shares could be decrypted and verified\n");
        } else {
            printf("NOT OK Test 3 - 2: failed to decrypt %d shares, and failed to verify %d shares\n", num_failed_decryptions, num_failed_verifications);
        }
    }
    
    // cleanup
    BN_CTX_free(ctx);
    dh_pvss_ctx_free(&pp);
    point_free(secret);
    dh_key_pair_free(&first_dist_kp);
    for (int i=0; i<n; i++){
        dh_key_pair_free(&committee_key_pairs[i]);
        point_free(encrypted_shares[i]);
        point_free(decrypted_shares[i]);
    }
    nizk_dl_eq_proof_free(&distribution_pi);
    
    return !(ret1 == 0 && num_failed_decryptions == 0 && num_failed_verifications == 0);
}

static int dh_pvss_test_4(int print) {
    
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    
    // setup
    const int t = 1;
    const int n = 4;
    dh_pvss_ctx pp;
    dh_pvss_setup(&pp, group, t, n, ctx);
    EC_POINT *secret = point_random(group, ctx);

    printf("secret: ");
    point_print(group, secret, ctx);
    printf("\n");
    
    // keygen
    dh_key_pair first_dist_kp;
    dh_key_pair_generate(group, &first_dist_kp, ctx);
//    dh_DEBUG_key_pair_generate(group, &first_dist_kp, 4, ctx);
    dh_key_pair committee_key_pairs[n];
    dh_key_pair dist_key_pairs[n];
    EC_POINT *committee_public_keys[n];
    EC_POINT *dist_public_keys[n];
    for (int i=0; i<n; i++) {
        dh_key_pair *com_member_key_pair = &committee_key_pairs[i];
        dh_key_pair *dist_key_pair = &dist_key_pairs[i];
        dh_key_pair_generate(group, com_member_key_pair, ctx);
//        dh_DEBUG_key_pair_generate(group, com_member_key_pair, 5, ctx);
        dh_key_pair_generate(group, dist_key_pair, ctx);
//        dh_DEBUG_key_pair_generate(group, dist_key_pair, 5, ctx);
        committee_public_keys[i] = com_member_key_pair->pub;
        dist_public_keys[i] = dist_key_pair->pub;
    }
    
    // make encrypted shares with proof
    EC_POINT *encrypted_shares[n];
    nizk_dl_eq_proof distribution_pi;
    dh_pvss_distribute_prove(&pp, encrypted_shares, &first_dist_kp, (const EC_POINT**)committee_public_keys, secret, &distribution_pi);
    
    // positive test verify encrypted shares
    int ret1 = dh_pvss_distribute_verify(&pp, &distribution_pi, (const EC_POINT**)encrypted_shares, first_dist_kp.pub, (const EC_POINT**)committee_public_keys);
    if (print) {
        printf("%6s Test 4 - 1: Correct DH PVSS Distribution Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }
    
    // negative test verify encrypted shares
    int ret1b = dh_pvss_distribute_verify(&pp, &distribution_pi, (const EC_POINT**)encrypted_shares, committee_public_keys[0], (const EC_POINT**)committee_public_keys);
    if (print) {
        if (ret1b) {
            printf("    OK Test 4 - 2: Incorrect DH PVSS Reshare Proof not accepted (which is CORRECT)\n");
        } else {
            printf("NOT OK Test 4 - 2: Incorrect DH PVSS Reshare Proof IS accepted (which is an ERROR)\n");
        }
    }
    
    // decrypting the encrypted shares and verifiying
    EC_POINT *decrypted_shares[n];
    int num_failed_decryptions = 0;
    int num_failed_verifications = 0;
    for (int i=0; i<n; i++) {
        nizk_dl_eq_proof committee_member_pi;
        decrypted_shares[i] = dh_pvss_decrypt_share_prove(group, first_dist_kp.pub, &committee_key_pairs[i], encrypted_shares[i], &committee_member_pi, ctx);
        if (decrypted_shares[i] == NULL) {
            num_failed_decryptions++;
            if (print) {
                printf("failed to decrypt an encrypted share\n");
            }
        }
        int ret2 = dh_pvss_decrypt_share_verify(group, first_dist_kp.pub, committee_public_keys[i], encrypted_shares[i], decrypted_shares[i], &committee_member_pi, ctx);
        if (ret2) {
            num_failed_verifications++;
            if (print) {
                printf("failed to verify a decrypted share\n");
            }
        }
        
        // cleanup
        nizk_dl_eq_proof_free(&committee_member_pi);
    }
    if (print) {
        if (num_failed_decryptions == 0 && num_failed_verifications == 0) {
            printf("    OK Test 4 - 3: all encrypted shares could be decrypted and verified\n");
        } else {
            printf("NOT OK Test 4 - 3: failed to decrypt %d shares, and failed to verify %d shares\n", num_failed_decryptions, num_failed_verifications);
        }
    }
    
    // reconstruct secret
    EC_POINT *reconstruction_shares[t+1];
    int reconstruction_indices[t+1];
    int first = 2;
    for (int i=first; i<first+t+1; i++) {
        reconstruction_shares[i-first] = decrypted_shares[i];
        int pp_alpha_as_int = (int)BN_get_word(pp.alphas[i+1]); // this works since alphas were chosen small enough to fit in an int
        reconstruction_indices[i-first] = pp_alpha_as_int;
    }
    
    EC_POINT *reconstructed_secret = dh_pvss_reconstruct(group, (const EC_POINT**)reconstruction_shares, reconstruction_indices, pp.t, t+1, ctx);
    int ret3 = point_cmp(group, secret, reconstructed_secret, ctx); // zero if equal
    if (print) {
        printf("%6s Test 4 - 4: Correct DH PVSS reconstruction %s accepted\n", ret3 ? "NOT OK" : "OK", ret3 ? "NOT" : "indeed");
    }
    
    // setup for next epoch committe
    // TODO: try changing the size of the next epoch committee
    dh_pvss_ctx next_pp;
    dh_pvss_setup(&next_pp, group, t, n, ctx);
    
    // keygen for next epoch committe
    dh_key_pair next_committee_key_pairs[n];
    EC_POINT *next_committee_public_keys[n];
    for (int i=0; i<next_pp.n; i++) {
        dh_key_pair *next_com_member_key_pair = &next_committee_key_pairs[i];
        dh_key_pair_generate(group, next_com_member_key_pair, ctx);
//        dh_DEBUG_key_pair_generate(group, next_com_member_key_pair, 5, ctx);
        next_committee_public_keys[i] = next_com_member_key_pair->pub;
    }
    
    // make a single reshare
    int party_index = 3;
    EC_POINT *encrypted_re_shares[next_pp.n];
    nizk_reshare_proof reshare_pi;
    dh_pvss_reshare_prove(group, party_index, &committee_key_pairs[party_index], &dist_key_pairs[party_index], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, pp.n, &next_pp, (const EC_POINT**)next_committee_public_keys, encrypted_re_shares, &reshare_pi, ctx);
    
    // positive test for reshare
    int ret4 = dh_pvss_reshare_verify(&pp, &next_pp, party_index, committee_public_keys[party_index], dist_public_keys[party_index], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, (const EC_POINT**)next_committee_public_keys, encrypted_re_shares, &reshare_pi);
    if (print) {
        printf("%6s Test 4 - 5: Correct DH PVSS Reshare Proof %s accepted\n", ret4 ? "NOT OK" : "OK", ret4 ? "NOT" : "indeed");
    }
    
    // negative test for reshare
    int ret5 = dh_pvss_reshare_verify(&pp, &next_pp, party_index, committee_public_keys[party_index], committee_public_keys[party_index], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, (const EC_POINT**)next_committee_public_keys, encrypted_re_shares, &reshare_pi);
    if (print) {
        if (ret5) {
            printf("    OK Test 4 - 6: Incorrect DH PVSS Reshare Proof not accepted (which is CORRECT)\n");
        } else {
            printf("NOT OK Test 4 - 6: Incorrect DH PVSS Reshare Proof IS accepted (which is an ERROR)\n");
        }
    }
    
    // the below will make a full reshare -> reconstruct reshare -> decrypt shares -> reconstruct, and then finally see it the correct secret is reconstructed
    
    // 1. make a reshare for all parties
    EC_POINT *all_encrypted_re_shares[pp.n][next_pp.n];
    nizk_reshare_proof reshare_pis[pp.n];
    for (int i = 0; i<pp.n; i++) {
        if ((i+1)%10 == 0){
            printf("       Test 4 - X: reshare progress: %d of %d \n",i+1, pp.n);
        }
        dh_pvss_reshare_prove(group, i, &committee_key_pairs[i], &dist_key_pairs[i], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, pp.n, &next_pp, (const EC_POINT**)next_committee_public_keys, all_encrypted_re_shares[i], &reshare_pis[i], ctx);
        printf("%dth reshare: ", i);
        for (int j=0; j<t+1; j++) {
            point_print(group, all_encrypted_re_shares[i][j], ctx);
        }
        //verify the reshare
        int valid_res_share = dh_pvss_reshare_verify(&pp, &next_pp, i, (const EC_POINT*) committee_public_keys[i], (const EC_POINT*) dist_public_keys[i], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, (const EC_POINT**)next_committee_public_keys, all_encrypted_re_shares[i], &reshare_pis[i]);
        printf("%6s reshare", valid_res_share ? "NOT OK" : "OK");

        printf("\n");
    }
    
    // 2. reconstruct reshare
    int valid_indices[pp.t+1];
    for (int i = 0; i<pp.t+1; i++) {
        valid_indices[i] = i+1; // assume all indices valid for this test
    }
    EC_POINT *reconstructed_encrypted_reshares[next_pp.n];
    for (int j = 0; j<next_pp.n; j++) { // loop over slices

        EC_POINT *slice_of_encrypted_reshares[next_pp.t+1];
        for (int i=0; i<next_pp.t+1; i++) { // get the the j:th share from all n rehares
            slice_of_encrypted_reshares[i] = all_encrypted_re_shares[ valid_indices[i] - 1 ][j];
        }

        printf("%d:th slice of encrypted reshare: ", j);
        for (int i = 0; i<t+1; i++) { // loop over slice
            point_print(group, slice_of_encrypted_reshares[i], ctx);
        }
        printf("\n");
        printf("valid_indices:");
        for (int i = 0; i<t+1; i++) { // loop over slice
            printf(" %d", valid_indices[i]);
        }
        printf("\n");
        fflush(stdout);
        
        reconstructed_encrypted_reshares[j] = dh_pvss_reconstruct_reshare(&pp, next_pp.t+1, valid_indices, slice_of_encrypted_reshares);

        printf("%d:th reconstructed: ",j);
        point_print(group, reconstructed_encrypted_reshares[j], ctx);
        printf("\n");
    }
    
    // 3. decrypt reconstructed reshares
    
    int reshare_reconstruction_indices[next_pp.t+1];
    EC_POINT *reshare_reconstruction_keys[next_pp.t+1];
    dh_key_pair *reshare_reconstruction_keys_pairs[next_pp.t+1];
    EC_POINT *reshare_reconstruction_shares[next_pp.t+1];
//    TODO: the below assignment that first = 0 ruins the test... wierd
    first = 0;
    for (int i=first; i<first+next_pp.t+1; i++) { // fill indexes and keys
        int pp_alpha_as_int = (int)BN_get_word(pp.alphas[i+1]); // this works since alphas were chosen small enough to fit in an int
        reshare_reconstruction_indices[i-first] = pp_alpha_as_int;
        reshare_reconstruction_keys[i-first] = committee_public_keys[i];
        reshare_reconstruction_keys_pairs[i-first] = &committee_key_pairs[i];
        // TODO: the below i-1 should be i right? but it doesnt work...
        reshare_reconstruction_shares[i-first] = reconstructed_encrypted_reshares[i];
    }
    printf("RECON inDICES:\n");
    for (int i = 0; i<t+1; i++) {
        printf("%d\n",reshare_reconstruction_indices[i]);
    }

    print_allocation_status();

    EC_POINT *prev_dist_pub_key = dh_pvss_committee_dist_key_calc(group, (const EC_POINT**) reshare_reconstruction_keys, reshare_reconstruction_indices, next_pp.t, next_pp.t+1, ctx);
    EC_POINT *decrypted_reshares[next_pp.t+1];
    for (int i=0; i<next_pp.t+1; i++) {
        nizk_dl_eq_proof decrypt_pi;
        decrypted_reshares[i] = dh_pvss_decrypt_share_prove(group, prev_dist_pub_key, reshare_reconstruction_keys_pairs[i], reshare_reconstruction_shares[i], &decrypt_pi, ctx);//decrypted_shares[i-1];
        // TODO: this test should not fail, since decryption works...
        int decrypt_test = dh_pvss_decrypt_share_verify(group, prev_dist_pub_key, reshare_reconstruction_keys[i], encrypted_shares[i], decrypted_shares[i], &decrypt_pi, ctx);
        printf("%6s decrypt recon reshare\n", decrypt_test ? "NOT OK" : "OK");

        nizk_dl_eq_proof_free(&decrypt_pi);
    }
    
    print_allocation_status();

    // 4. reconstruct and compare
    EC_POINT *reconstructed_reshared = dh_pvss_reconstruct(group, (const EC_POINT **)decrypted_reshares, reshare_reconstruction_indices, next_pp.t, next_pp.t+1, ctx);
    int ret6 = point_cmp(group, secret, reconstructed_reshared, ctx); // zero if equal
    if (print) {
        printf("%6s Test 4 - 7: Correct reconstruction of reshared secret %s accepted\n", ret6 ? "NOT OK" : "OK", ret6 ? "NOT" : "indeed");
    }
    printf("secret: ");
    point_print(group, secret, ctx);
    printf("\n");
    printf("reconstructed_reshared: ");
    point_print(group, reconstructed_reshared, ctx);
    printf("\n");

    // cleanup
    BN_CTX_free(ctx);
    dh_pvss_ctx_free(&pp);
    point_free(secret);
    dh_key_pair_free(&first_dist_kp);
    for (int i=0; i<n; i++){
        dh_key_pair_free(&committee_key_pairs[i]);
        dh_key_pair_free(&dist_key_pairs[i]);
        point_free(encrypted_shares[i]);
        point_free(decrypted_shares[i]);
        dh_key_pair_free(&next_committee_key_pairs[i]);
    }
    nizk_dl_eq_proof_free(&distribution_pi);
    point_free(reconstructed_secret);
    for (int i=0; i<next_pp.n; i++){
        point_free(encrypted_re_shares[i]);
    }
    nizk_reshare_proof_free(&reshare_pi);
    for (int j = 0; j<next_pp.n; j++) {
        for (int i = 0; i<pp.n; i++) { // get the the j:th share from all n rehares
            point_free(all_encrypted_re_shares[i][j]);
        }
    }
    for (int i=0; i<pp.n; i++){
        nizk_reshare_proof_free(&reshare_pis[i]);
    }
    for (int i=0; i<next_pp.n; i++){
        point_free(reconstructed_encrypted_reshares[i]);
    }
    point_free(prev_dist_pub_key);
    for (int i = 0; i<next_pp.t+1; i++){
        point_free(decrypted_reshares[i]);
    }
    point_free(reconstructed_reshared);
    
    return !(ret1 == 0 && ret1b != 0 &&num_failed_decryptions == 0 && num_failed_verifications == 0 && ret3 == 0 && ret4 == 0 && ret5 != 0 && ret6 == 0);
}

typedef int (*test_function)(int);

static test_function test_suite[] = {
    &dh_pvss_test_1,
    &dh_pvss_test_2,
    &dh_pvss_test_3,
    &dh_pvss_test_4
};

// return test results
//   0 = passed (all individual tests passed)
//   1 = failed (one or more individual tests failed)
// setting print to 0 (zero) suppresses stdio printouts, while print 1 is 'verbose'
int dh_pvss_test_suite(int print) {
    if (print) {
        printf("DH PVSS test suite\n");
        print_allocation_status();
    }
    int num_tests = sizeof(test_suite)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite[i](print)) {
            ret = 1;
        }
        print_allocation_status();
    }
    if (print) {
        print_allocation_status();
        fflush(stdout);
    }
    return ret;
}
