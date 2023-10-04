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
#include <string.h>

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

void dh_pvss_setup(dh_pvss_ctx *pp, const EC_GROUP *group, const int t, const int n, BN_CTX *bn_ctx) {
    assert(group && "dh_pvss_setup: usage error, no group specified");
    pp->group = group;
    assert(bn_ctx && "dh_pvss_setup: usage error, no BIGNUM context specified");
    pp->bn_ctx = bn_ctx;
    assert( (n - t - 2) > 0 && "dh_pvss_setup: usage error, n and t badly chosen");
    pp->t = t;
    pp->n = n;

    // allocate vectors
    pp->alphas   = malloc(sizeof(BIGNUM *) * (n + 1));
    pp->betas    = malloc(sizeof(BIGNUM *) * (n + 1));
    pp->v_primes = malloc(sizeof(BIGNUM *) * (n + 1));
    pp->vs       = malloc(sizeof(BIGNUM *) * n);
    assert(pp->alphas && "dh_pvss_setup: allocation error alphas");
    assert(pp->betas && "dh_pvss_setup: allocation error betas");
    assert(pp->v_primes && "dh_pvss_setup: allocation error v_primes");
    assert(pp->vs && "dh_pvss_setup: allocation error vs");

    // allocate vector entries
    for (int i=0; i<n+1; i++) {
        pp->alphas[i]   = BN_new();
        pp->betas[i]    = BN_new();
        pp->v_primes[i] = BN_new();
        assert(pp->alphas[i] && "dh_pvss_setup: allocation error for entry in alphas");
        assert(pp->betas[i] && "dh_pvss_setup: allocation error for entry in betas");
        assert(pp->v_primes[i] && "dh_pvss_setup: allocation error for entry in v_primes");
    }
    for (int i=0; i<n; i++) {
        pp->vs[i] = BN_new();
        assert(pp->vs[i] && "dh_pvss_setup: allocation error for entry in vs");
    }

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

    BIGNUM *poly_eval = BN_new();
    BIGNUM *poly_term = BN_new();
    BIGNUM *exp       = BN_new();
    assert(poly_eval && "generate_scrape_sum_terms: allocation error for poly_eval");
    assert(poly_term && "generate_scrape_sum_terms: allocation error for poly_term");
    assert(exp && "generate_scrape_sum_terms: allocation error for exp");
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
        assert(terms[x - 1] && "generate_scrape_sum_terms: allocation error for terms");
        BN_mod_mul(terms[x - 1], code_coeffs[x - 1], poly_eval, order, ctx);
    }

    // cleanup
    BN_free(poly_eval);
    BN_free(poly_term);
    BN_free(exp);
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
        EC_POINT *encrypted_share = encrypted_shares[i] = EC_POINT_new(group);
        assert(encrypted_share && "dh_pvss_distribute_prove: allocation error for encrypted_share");
        point_mul(group, encrypted_share, dist_key->priv, com_keys[i], ctx);
        point_add(group, encrypted_share, encrypted_share, shares[i], ctx);
    }

    // degree n-t-2 polynomial = hash(dist_key->pub, com_keys)
    const int num_poly_coeffs = n - t - 1;
    BIGNUM *poly_coeffs[num_poly_coeffs]; // polynomial container
    
    openssl_hash_points2poly_2(group, ctx, num_poly_coeffs, poly_coeffs, dist_key->pub, n, com_keys, (const EC_POINT**)encrypted_shares);

    // generate scrape sum terms
    BIGNUM *scrape_terms[n];
    generate_scrape_sum_terms(group, scrape_terms, pp->alphas, pp->vs, poly_coeffs, n, num_poly_coeffs, ctx);

    // compute U and V
    EC_POINT *U = EC_POINT_new(group);
    EC_POINT *V = EC_POINT_new(group);
    assert(U && "dh_pvss_distribute_prove: allocation error for U");
    assert(V && "dh_pvss_distribute_prove: allocation error for V");
    point_weighted_sum(group, U, n, (const BIGNUM**)scrape_terms, com_keys, ctx);
    point_weighted_sum(group, V, n, (const BIGNUM**)scrape_terms, (const EC_POINT**)encrypted_shares, ctx);

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
    for (int i=0; i<num_poly_coeffs; i++) {
        BN_free(poly_coeffs[i]);
    }
    
    // implicitly return (pi, encrypted_shares)
}

int dh_pvss_distribute_verify(dh_pvss_ctx *pp, nizk_dl_eq_proof *pi, const EC_POINT **enc_shares, const EC_POINT *pub_dist, const EC_POINT **com_keys) {
    const EC_GROUP *group = pp->group;
    BN_CTX *ctx = pp->bn_ctx;
    const EC_POINT *generator = get0_generator(group);
    const int n = pp->n;
    const int t = pp->t;

    // degree n-t-2 polynomial <- hash(dist_key->pub, com_keys)
    const int num_poly_coeffs = n - t - 1;
    BIGNUM *poly_coeffs[num_poly_coeffs]; // polynomial container
    openssl_hash_points2poly_2(group, ctx, num_poly_coeffs, poly_coeffs, pub_dist, n, com_keys, (const EC_POINT**)enc_shares);

    // generate scrape sum terms
    BIGNUM *scrape_terms[n];
    generate_scrape_sum_terms(group, scrape_terms, pp->alphas, pp->vs, poly_coeffs, n, num_poly_coeffs, ctx);

    // compute U and V
    EC_POINT *U = EC_POINT_new(group);
    EC_POINT *V = EC_POINT_new(group);
    assert(U && "dh_pvss_distribute_verify: allocation error for U");
    assert(V && "dh_pvss_distribute_verify: allocation error for V");
    point_weighted_sum(group, U, n, (const BIGNUM**)scrape_terms, com_keys, ctx);
    point_weighted_sum(group, V, n, (const BIGNUM**)scrape_terms, enc_shares, ctx);

    // verify dl eq proof
    int ret = nizk_dl_eq_verify(group, generator, pub_dist, U, V, pi, ctx);

    // cleanup
    EC_POINT_free(U);
    EC_POINT_free(V);
    for (int i=0; i<n; i++) {
        BN_free(scrape_terms[i]);
    }
    for (int i=0; i<num_poly_coeffs; i++) {
        BN_free(poly_coeffs[i]);
    }

    return ret;
}

static EC_POINT *dh_pvss_decrypt_share_prove(const EC_GROUP *group, const EC_POINT *dist_key_pub, dh_key_pair *C, const EC_POINT *encrypted_share, nizk_dl_eq_proof *pi, BN_CTX *ctx) {
    const EC_POINT *generator = get0_generator(group);

    // compute shared key
    EC_POINT *shared_key = EC_POINT_new(group);
    assert(shared_key && "dh_pvss_decrypt_share: allocation error for shared_key");
    point_mul(group, shared_key, C->priv, dist_key_pub, ctx);

    // decrypt share
    EC_POINT *decrypted_share = EC_POINT_new(group);
    assert(decrypted_share && "dh_pvss_decrypt_share: allocation error for decrypted_share");
    point_sub(group, decrypted_share, encrypted_share, shared_key, ctx);

    // compute difference
    EC_POINT *diff = EC_POINT_new(group);
    assert(diff && "dh_pvss_decrypt_share: allocation error for diff");
    point_sub(group, diff, encrypted_share, decrypted_share, ctx);

    // prove correct decryption
    nizk_dl_eq_prove(group, C->priv, generator, C->pub, dist_key_pub, diff, pi, ctx);
    
    // cleanup
    EC_POINT_free(diff);
    EC_POINT_free(shared_key);

    return decrypted_share; // return decrypted share and (implicitly) proof
}

static int dh_pvss_decrypt_share_verify(const EC_GROUP *group, const EC_POINT *dist_key_pub, const EC_POINT *C_pub, const EC_POINT *encrypted_share, const EC_POINT *decrypted_share, nizk_dl_eq_proof *pi, BN_CTX *ctx) {
    const EC_POINT *generator = get0_generator(group);

    // compute difference
    EC_POINT *diff = EC_POINT_new(group);
    assert(diff && "dh_pvss_decrypt_share: allocation error for diff");
    point_sub(group, diff, encrypted_share, decrypted_share, ctx);

    // prove correct decryption
    int ret = nizk_dl_eq_verify(group, generator, C_pub, dist_key_pub, diff, pi, ctx);
    
    // cleanup
    EC_POINT_free(diff);

    return ret; // return proof verification result
}

EC_POINT *dh_pvss_reconstruct(const EC_GROUP *group, const EC_POINT *shares[], int share_indexes[], int t, int length, BN_CTX *ctx){
    // decrypted shares are plain shamir shares, so we just call shamir reconstruct
    return shamir_shares_reconstruct(group, shares, share_indexes, t, length, ctx);
}

EC_POINT *dh_pvss_committee_dist_key_calc(const EC_GROUP *group, const EC_POINT *keys[], int key_indices[], int t, int length, BN_CTX *ctx) {
    // the implementation of this is identical to shamir reconstruct, so we call shamir reconstuct, but with keys instead of shares
    return shamir_shares_reconstruct(group, keys, key_indices, t, length, ctx);
}

static void dh_pvss_reshare_prove(const EC_GROUP *group, int party_index, const dh_key_pair *party_committee_kp, const dh_key_pair *party_dist_kp, const EC_POINT *previous_dist_key, const EC_POINT *current_enc_shares[], const int current_n, const dh_pvss_ctx *next_pp, const EC_POINT *next_committee_keys[], EC_POINT *enc_re_shares[], nizk_reshare_proof *pi, BN_CTX *ctx) {
    
    const EC_POINT *generator = get0_generator(group);
   
    // compute shared key
    EC_POINT *shared_key = EC_POINT_new(group);
    assert(shared_key && "dh_pvss_reshare_prove: allocation error for shared_key");
    point_mul(group, shared_key, party_committee_kp->priv, previous_dist_key, ctx);

    // decrypt share
    EC_POINT *decrypted_share = EC_POINT_new(group);
    assert(decrypted_share && "dh_pvss_reshare_prove: allocation error for decrypted_share");
    point_sub(group, decrypted_share, current_enc_shares[party_index], shared_key, ctx);
    
    // create shares of it for next epoch committe
    EC_POINT *re_shares[next_pp->n];
    shamir_shares_generate(group, re_shares, decrypted_share, next_pp->t, next_pp->n, ctx);
    
    // encrypt the re_shares for the next epoch committee public keys
    EC_POINT *enc_shared_key = EC_POINT_new(group);
    assert(enc_shared_key && "dh_pvss_reshare_prove: allocation error for enc_shared_key");
    for (int i = 0; i<next_pp->n; i++) {
        point_mul(group, enc_shared_key, party_dist_kp->priv, next_committee_keys[i], ctx);
        enc_re_shares[i] = EC_POINT_new(group);
        point_add(group, enc_re_shares[i], enc_shared_key, re_shares[i], ctx);
    }
    
    // degree n-t-1 polynomial <- hash(previous_dist_key, current_enc_shares)
    const int num_poly_coeffs = next_pp->n - next_pp->t;
    BIGNUM *poly_coeffs[num_poly_coeffs]; // polynomial container
    openssl_hash_points2poly_1(group, ctx, num_poly_coeffs, poly_coeffs, previous_dist_key, current_n, current_enc_shares);
    
    // generate scrape sum terms
    BIGNUM *scrape_terms[next_pp->n];
    generate_scrape_sum_terms(group, scrape_terms, next_pp->betas, next_pp->v_primes, poly_coeffs, next_pp->n, num_poly_coeffs, ctx);
    
    // compute U', V' and W'
    EC_POINT *enc_re_share_diffs[next_pp->n];
    for (int i = 0; i<next_pp->n; i++) {
        enc_re_share_diffs[i] = EC_POINT_new(group);
        point_sub(group, enc_re_share_diffs[i], enc_re_shares[i], current_enc_shares[party_index], ctx);
    }
    EC_POINT *U_prime = EC_POINT_new(group);
    EC_POINT *V_prime = EC_POINT_new(group);
    EC_POINT *W_prime = EC_POINT_new(group);
    assert(U_prime && "dh_pvss_reshare_prove: allocation error for U_prime");
    assert(V_prime && "dh_pvss_reshare_prove: allocation error for V_prime");
    assert(W_prime && "dh_pvss_reshare_prove: allocation error for V_prime");
    
    point_weighted_sum(group, U_prime, next_pp->n, (const BIGNUM**)scrape_terms, enc_re_share_diffs, ctx);
    point_weighted_sum(group, V_prime, next_pp->n, (const BIGNUM**)scrape_terms, next_committee_keys, ctx);
    BIGNUM *W_sum = BN_new();
    for (int i = 0; i<next_pp->n; i++) {
        BN_add(W_sum, W_sum, scrape_terms[i]);
    }
    point_mul(group, W_prime, W_sum, previous_dist_key, ctx);
    
    // prove correctness
    nizk_reshare_prove(group, party_committee_kp->priv, party_dist_kp->priv, generator, V_prime, W_prime, party_committee_kp->pub, party_dist_kp->pub, U_prime, pi, ctx);
    
    // cleanup
    for (int i = 0; i<next_pp->n; i++) {
        EC_POINT_free(re_shares[i]);
    }
    EC_POINT_free(enc_shared_key);
    for (int i = 0; i<num_poly_coeffs; i++) {
        BN_free(poly_coeffs[i]);
    }
    for (int i = 0; i<next_pp->n; i++) {
        BN_free(scrape_terms[i]);
    }
    for (int i = 0; i<next_pp->n; i++) {
        EC_POINT_free(enc_re_share_diffs[i]);
    }
    EC_POINT_free(U_prime);
    EC_POINT_free(V_prime);
    BN_free(W_sum);
    EC_POINT_free(W_prime);

    
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
    for (int i = 0; i<n; i++) {
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
        printf("Test 1 %s: Correct DH PVSS Distribution Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // cleanup
    BN_CTX_free(ctx);
    dh_pvss_ctx_free(&pp);
    EC_POINT_free(secret);
    dh_key_pair_free(&first_dist_kp);
    for (int i = 0; i<n; i++){
        dh_key_pair_free(&committee_key_pairs[i]);
        EC_POINT_free(enc_shares[i]);
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
    for (int i = 0; i<n; i++) {
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
        printf("Test 2 part 1 %s: Correct DH PVSS Distribution Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }
    
    //negative test
    int ret2 = dh_pvss_distribute_verify(&pp, &pi, (const EC_POINT**)enc_shares, committee_public_keys[0], (const EC_POINT**)committee_public_keys);
    if (print) {
        if (ret2) {
            printf("Test 2 part 2 OK: Incorrect NIZK DL Proof not accepted (which is CORRECT)\n");
        } else {
            printf("Test 2 part 2 NOT OK: Incorrect NIZK DL Proof IS accepted (which is an ERROR)\n");
        }
    }
    
    // cleanup
    BN_CTX_free(ctx);
    dh_pvss_ctx_free(&pp);
    EC_POINT_free(secret);
    dh_key_pair_free(&first_dist_kp);
    for (int i = 0; i<n; i++){
        dh_key_pair_free(&committee_key_pairs[i]);
        EC_POINT_free(enc_shares[i]);
    }
    nizk_dl_eq_proof_free(&pi);
    
    return 0;// success
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
        printf("Test 3 part 1 %s: Correct DH PVSS Distribution Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
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
            printf("Test 3 part 2 OK: all encrypted shares could be decrypted and verified\n");
        } else {
            printf("Test 3 part 2 NOT OK: failed to decrypt %d shares, and failed to verify %d shares\n", num_failed_decryptions, num_failed_verifications);
        }
    }

    // cleanup
    BN_CTX_free(ctx);
    dh_pvss_ctx_free(&pp);
    EC_POINT_free(secret);
    dh_key_pair_free(&first_dist_kp);
    for (int i=0; i<n; i++){
        dh_key_pair_free(&committee_key_pairs[i]);
        EC_POINT_free(encrypted_shares[i]);
    }
    nizk_dl_eq_proof_free(&distribution_pi);
    
    return !(ret1 == 0 && num_failed_decryptions == 0 && num_failed_verifications == 0);
}

static int dh_pvss_test_4(int print) {
//    dh_pvss_reshare_prove(const EC_GROUP *group, int party_index, const dh_key_pair *party_committee_kp, const dh_key_pair *party_dist_kp, const EC_POINT *previous_dist_key, const EC_POINT *current_enc_shares[], const int current_n, const dh_pvss_ctx *next_pp, const EC_POINT *next_committee_keys[], EC_POINT *enc_re_shares[], nizk_reshare_proof *pi, BN_CTX *ctx)
    
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
    dh_pvss_distribute_prove(group, encrypted_shares, &pp, &first_dist_kp, (const EC_POINT**)committee_public_keys, secret, &distribution_pi, ctx);

    // verify encrypted shares
    int ret1 = dh_pvss_distribute_verify(group, &distribution_pi, (const EC_POINT**)encrypted_shares, &pp, first_dist_kp.pub, (const EC_POINT**)committee_public_keys, ctx);
    if (print) {
        printf("Test 4 part 1 %s: Correct DH PVSS Distribution Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
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
            printf("Test 4 part 2 OK: all encrypted shares could be decrypted and verified\n");
        } else {
            printf("Test 4 part 2 NOT OK: failed to decrypt %d shares, and failed to verify %d shares\n", num_failed_decryptions, num_failed_verifications);
        }
    }
    
    // reconstruct secret
    EC_POINT *reconstruction_shares[t+1];
    int reconstruction_indexes[t+1];
    memcpy(reconstruction_shares, decrypted_shares[5],(t+1) * sizeof(EC_POINT*));
    memcpy(reconstruction_indexes, pp.alphas[5],(t+1) * sizeof(int));
    EC_POINT *reconstructed_secret = dh_pvss_reconstruct(group, reconstruction_shares, reconstruction_indexes, pp.t, t+1, ctx);
    int ret2 = point_cmp(group, secret, reconstructed_secret, ctx);
    if (print) {
        printf("Test 4 part 1 %s: Correct DH PVSS Distribution Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }
    
    

    // cleanup
    BN_CTX_free(ctx);
    dh_pvss_ctx_free(&pp);
    EC_POINT_free(secret);
    dh_key_pair_free(&first_dist_kp);
    for (int i=0; i<n; i++){
        dh_key_pair_free(&committee_key_pairs[i]);
        EC_POINT_free(encrypted_shares[i]);
    }
    nizk_dl_eq_proof_free(&distribution_pi);
    EC_POINT_free(reconstructed_secret);
    
    return !(ret1 == 0 && num_failed_decryptions == 0 && num_failed_verifications == 0 && ret2 != 0);
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
    }
    int num_tests = sizeof(test_suite)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite[i](print)) {
            ret = 1;
        }
    }
    if (print) {
        fflush(stdout);
    }
    return ret;
}
