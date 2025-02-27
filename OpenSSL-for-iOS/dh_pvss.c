//
//  dh_pvss.c
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-10-01.
//
#include "dh_pvss.h"
#include <assert.h>
#include "SSS.h"
#include "openssl_hashing_tools.h"
#include "platform_measurement_utils.h"

#ifdef DEBUG
void nizk_print_allocation_status(void) {
    nizk_dl_print_allocation_status();
    nizk_dl_eq_print_allocation_status();
    nizk_reshare_print_allocation_status();
}
#endif

void dh_pvss_ctx_free(dh_pvss_ctx *pp) {
    bn_free_array(pp->n+1, pp->alphas);
    bn_free_array(pp->n+1, pp->betas);
    bn_free_array(pp->n+1, pp->v_primes);
    bn_free_array(pp->n, pp->vs);
}

/* make deep copy of dh pvss ctx
 * useful when initializing dh pvss ctx for next epoch, when the same n is used, because then scrape coefficients do not need to be recalculated (they depend only on n) */
void dh_pvss_ctx_copy(dh_pvss_ctx *dst, dh_pvss_ctx *src, int t) {
    assert(src && "dh_pvss_ctx_copy: usage error, no src");
    assert(dst && "dh_pvss_ctx_copy: usage error, no dst");
    dst->group = src->group;
    dst->bn_ctx = src->bn_ctx;
    int n = src->n;
    assert( (n - t - 2) > 0 && "dh_pvss_setup: usage error, n and t badly chosen");
    dst->t = t;
    dst->n = n;

    // copy vectors
    dst->alphas   = bn_copy_array(src->alphas, n+1);
    dst->betas    = bn_copy_array(src->betas, n+1);
    dst->v_primes = bn_copy_array(src->v_primes, n+1);
    dst->vs       = bn_copy_array(src->vs, n);
}

/* precompute table of small inverses
 *
 * inverse_table[0] = inverse of (-n+1) mod order
 * inverse_table[1] = inverse of (-n+2) mod order
 * ...
 * inverse_table[2n-2] = inverse of (n-1) mod order
 * inverse_table[2n-1] = inverse of (n) mod order
 */
static BIGNUM **precompute_inverse_table(const EC_GROUP *group, int n, BN_CTX *ctx) {
  const BIGNUM *order = get0_order(group);
  BIGNUM **inverse_table = bn_new_array(2*n);
  BIGNUM *a = bn_new();
  BN_set_word(a, n); // a:= n
  BIGNUM *one = bn_new();
  BN_set_word(one, 1); // one := 1
  BN_mod_sub(a, one, a, order, ctx); // a := (1 - a) mod order, so a := (-n+1) mod order
  for (int i=0; i<2*n; i++) {
    BIGNUM *b = inverse_table[i];
    BN_mod_inverse(b, a, order, ctx);
    BN_mod_add(a, a, one, order, ctx); // increase a by one
  }
  bn_free(one);
  bn_free(a);
  return inverse_table;
}

static void free_precompute_inverse_table(int n, BIGNUM **inverse_table) {
  bn_free_array(2*n, inverse_table);
}

static void derive_scrape_coeffs(const EC_GROUP *group, BIGNUM **coeffs, int from, int n, BIGNUM **inverse_table, BN_CTX *ctx) {
    const BIGNUM *order = get0_order(group);

    for (int i = 1; i <= n; i++) {
        BIGNUM *coeff = coeffs[i - 1];
        BN_set_word(coeff, 1);
        for (int j = from; j <= n; j++) {
            if (i == j) {
                continue;
            }
            int index = i-j+n-1;
            assert(index >= 0 && "bad index (too small)");
            assert(index < 2*n && "bad index (too big)");
            BN_mod_mul(coeff, coeff, inverse_table[index], order, ctx);
        }
    }
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
    BIGNUM **inverse_table = precompute_inverse_table(group, n, bn_ctx);
    derive_scrape_coeffs(group, pp->vs, 1, n, inverse_table, bn_ctx);
    derive_scrape_coeffs(group, pp->v_primes, 0, n, inverse_table, bn_ctx);
    free_precompute_inverse_table(n, inverse_table);
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
//    int num_points[num_point_lists] = {1, n, n};
//    const EC_POINT **point_lists[num_point_lists] = { (const EC_POINT **)&(dist_key->pub), com_keys, (const EC_POINT **)encrypted_shares};
    int num_points[3] = {1, n, n};
    const EC_POINT **point_lists[3] = { (const EC_POINT **)&(dist_key->pub), com_keys, (const EC_POINT **)encrypted_shares};
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
//    int num_points[num_point_lists] = {1, n, n};
//    const EC_POINT **point_lists[num_point_lists] = { &(pub_dist), com_keys, (const EC_POINT **)encrypted_shares};
    int num_points[3] = {1, n, n};
    const EC_POINT **point_lists[3] = { &(pub_dist), com_keys, (const EC_POINT **)encrypted_shares};
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
    point_mul(group, shared_key, party_committee_kp->priv, previous_dist_key, ctx);

    // decrypt share
    EC_POINT *decrypted_share = point_new(group);
    point_sub(group, decrypted_share, current_enc_shares[party_index], shared_key, ctx);

    // create shares of it for next epoch committe
    EC_POINT *re_shares[next_pp->n];
    shamir_shares_generate(group, re_shares, decrypted_share, next_pp->t, next_pp->n, ctx);

    // encrypt the re_shares for the next epoch committee public keys
    EC_POINT *enc_shared_key = point_new(group);
    for (int i = 0; i<next_pp->n; i++) {
        point_mul(group, enc_shared_key, party_dist_kp->priv, next_committee_keys[i], ctx);
        enc_re_shares[i] = point_new(group);
        point_add(group, enc_re_shares[i], enc_shared_key, re_shares[i], ctx);
    }

    // degree n-t-1 polynomial <- hash(previous_dist_key, current_enc_shares)
    const int num_poly_coeffs = next_pp->n - next_pp->t;
    BIGNUM *poly_coeffs[num_poly_coeffs]; // polynomial container
    const int num_point_lists = 2;
//    int num_points[num_point_lists] = {1, current_n};
//    const EC_POINT **point_lists[num_point_lists] = { &(previous_dist_key), current_enc_shares };
    int num_points[2] = {1, current_n};
    const EC_POINT **point_lists[2] = { &(previous_dist_key), current_enc_shares };
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
    point_free(decrypted_share);
    point_free(shared_key);
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
//    int num_points[num_point_lists] = {1, current_n};
//    const EC_POINT **point_lists[num_point_lists] = { &(previous_dist_key), current_enc_shares };
    int num_points[2] = {1, current_n};
    const EC_POINT **point_lists[2] = { &(previous_dist_key), current_enc_shares };
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
        BN_nnmod(lambda, lambda, order, ctx);
        point_mul(group, lambC, lambda, enc_re_shares[i], ctx);
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
    const int t = 5;
    const int n = 10;
    dh_pvss_ctx pp;
    dh_pvss_setup(&pp, group, t, n, ctx);
    EC_POINT *secret = point_random(group, ctx);

    // keygen
    dh_key_pair first_dist_kp;
    dh_key_pair_generate(group, &first_dist_kp, ctx);
    dh_key_pair committee_key_pairs[n];
    dh_key_pair dist_key_pairs[n];
    EC_POINT *committee_public_keys[n];
    EC_POINT *dist_public_keys[n];
    for (int i=0; i<n; i++) {
        dh_key_pair *com_member_key_pair = &committee_key_pairs[i];
        dh_key_pair *dist_key_pair = &dist_key_pairs[i];
        dh_key_pair_generate(group, com_member_key_pair, ctx);
        dh_key_pair_generate(group, dist_key_pair, ctx);
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
    for (int i=0; i<t+1; i++) {
        reconstruction_shares[i] = decrypted_shares[i + first];
        int pp_alpha_as_int = (int)BN_get_word(pp.alphas[i + first + 1]); // this works since alphas were chosen small enough to fit in an int
        reconstruction_indices[i] = pp_alpha_as_int;
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

    // the below will make a full reshare -> reconstruct reshare -> decrypt shares -> reconstruct, and then finally see if the correct secret is reconstructed

    // 1. make a reshare for all parties
    EC_POINT *all_encrypted_re_shares[pp.n][next_pp.n];
    nizk_reshare_proof reshare_pis[pp.n];
    for (int i = 0; i<pp.n; i++) {
        dh_pvss_reshare_prove(group, i, &committee_key_pairs[i], &dist_key_pairs[i], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, pp.n, &next_pp, (const EC_POINT**)next_committee_public_keys, all_encrypted_re_shares[i], &reshare_pis[i], ctx);

        //verify the reshare
        int valid_res_share = dh_pvss_reshare_verify(&pp, &next_pp, i, (const EC_POINT*) committee_public_keys[i], (const EC_POINT*) dist_public_keys[i], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, (const EC_POINT**)next_committee_public_keys, all_encrypted_re_shares[i], &reshare_pis[i]);
        if (valid_res_share) {
            printf("RESHARE NOT VALID, valid_res_share: %d\n", valid_res_share);
        }
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

        reconstructed_encrypted_reshares[j] = dh_pvss_reconstruct_reshare(&pp, next_pp.t+1, valid_indices, slice_of_encrypted_reshares);
    }

    // 3. decrypt reconstructed reshares

    int reshare_reconstruction_indices[next_pp.t+1];
    EC_POINT *reshare_reconstruction_keys[next_pp.t+1];
    EC_POINT *reshare_dist_keys[next_pp.t+1];
    dh_key_pair *reshare_reconstruction_keys_pairs[next_pp.t+1];
    EC_POINT *reshare_reconstruction_shares[next_pp.t+1];
    first = 0;
    for (int i=first; i<first+next_pp.t+1; i++) { // fill indexes and keys
        int pp_alpha_as_int = (int)BN_get_word(pp.alphas[i+1]); // this works since alphas were chosen small enough to fit in an int
        reshare_reconstruction_indices[i-first] = pp_alpha_as_int;
        reshare_reconstruction_keys[i-first] = next_committee_public_keys[i];
        reshare_dist_keys[i-first] = dist_public_keys[i];
        reshare_reconstruction_keys_pairs[i-first] = &next_committee_key_pairs[i];
        reshare_reconstruction_shares[i-first] = reconstructed_encrypted_reshares[i];
    }

    EC_POINT *prev_dist_pub_key = dh_pvss_committee_dist_key_calc(group, (const EC_POINT**) reshare_dist_keys, reshare_reconstruction_indices, next_pp.t, next_pp.t+1, ctx);
    EC_POINT *decrypted_reshares[next_pp.t+1];
    for (int i=0; i<next_pp.t+1; i++) {
        nizk_dl_eq_proof decrypt_pi;
        decrypted_reshares[i] = dh_pvss_decrypt_share_prove(group, prev_dist_pub_key, reshare_reconstruction_keys_pairs[i], reshare_reconstruction_shares[i], &decrypt_pi, ctx);//decrypted_shares[i-1];
        int decrypt_test = dh_pvss_decrypt_share_verify(group, prev_dist_pub_key, reshare_reconstruction_keys[i], reshare_reconstruction_shares[i], decrypted_reshares[i], &decrypt_pi, ctx);
        if (decrypt_test) {
            printf("COULD NOT VERIFY DECRYPTED SHARE, decrypt_test = %d\n", decrypt_test);
        }

        nizk_dl_eq_proof_free(&decrypt_pi);
    }

    // 4. reconstruct and compare
    EC_POINT *reconstructed_reshared = dh_pvss_reconstruct(group, (const EC_POINT **)decrypted_reshares, reshare_reconstruction_indices, next_pp.t, next_pp.t+1, ctx);
    int ret6 = point_cmp(group, secret, reconstructed_reshared, ctx); // zero if equal
    if (print) {
        printf("%6s Test 4 - 7: %s reconstruction of secret\n", ret6 ? "NOT OK" : "OK", ret6 ? "INCORRECT" : "correct");
    }

    // cleanup
    BN_CTX_free(ctx);
    dh_pvss_ctx_free(&pp);
    dh_pvss_ctx_free(&next_pp);
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
        printf("DH PVSS test suite BEGIN ----------------------------\n");
    }
    int num_tests = sizeof(test_suite)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite[i](print)) {
            ret = 1;
        }
    }
    if (print) {
        printf("DH PVSS test suite END ------------------------------\n");
#ifdef DEBUG
        print_allocation_status();
        nizk_print_allocation_status();
#endif
        fflush(stdout);
    }
    return ret;
}

int performance_test_with_correctness(double *results, int t, int n, int verbose) {

    int ret = 0;

    if (verbose) {
        printf("Running performance test with (n, t) = (%d, %d)\n", n, t);
    }

    /* setup & keygen */
    // setup
    platform_time_type start = platform_utils_get_wall_time();
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    dh_pvss_ctx pp;
    dh_pvss_setup(&pp, group, t, n, ctx);
    EC_POINT *secret = point_random(group, ctx);

    // keygen
    dh_key_pair first_dist_kp;
    dh_key_pair_generate(group, &first_dist_kp, ctx);
    dh_key_pair committee_key_pairs[n];
    dh_key_pair dist_key_pairs[n];
    EC_POINT *committee_public_keys[n];
    EC_POINT *dist_public_keys[n];
    for (int i=0; i<n; i++) {
        dh_key_pair *com_member_key_pair = &committee_key_pairs[i];
        dh_key_pair *dist_key_pair = &dist_key_pairs[i];
        dh_key_pair_generate(group, com_member_key_pair, ctx);
        dh_key_pair_generate(group, dist_key_pair, ctx);
        committee_public_keys[i] = com_member_key_pair->pub;
        dist_public_keys[i] = dist_key_pair->pub;
    }
    platform_time_type end = platform_utils_get_wall_time();
    double time_setup_and_keygen = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("setup & keygen: %f seconds\n", time_setup_and_keygen);
      fflush(stdout);
    }

    /* distribution phase (make encrypted shares with proofs) */
    start = platform_utils_get_wall_time();
    EC_POINT *encrypted_shares[n];
    nizk_dl_eq_proof distribution_pi;
    dh_pvss_distribute_prove(&pp, encrypted_shares, &first_dist_kp, (const EC_POINT**)committee_public_keys, secret, &distribution_pi);
    end = platform_utils_get_wall_time();
    double time_dist_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("distribute: %f seconds\n", time_dist_elapsed);
      fflush(stdout);
    }

    /* verifying encrypted shares */
    start = platform_utils_get_wall_time();
    ret += dh_pvss_distribute_verify(&pp, &distribution_pi, (const EC_POINT**)encrypted_shares, first_dist_kp.pub, (const EC_POINT**)committee_public_keys);
    end = platform_utils_get_wall_time();
    double time_dist_verify_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("verify distribution: %f seconds\n", time_dist_verify_elapsed);
      fflush(stdout);
    }

    /* decrypt a single share */
    start = platform_utils_get_wall_time();
    EC_POINT *dec_share;// = EC_POINT_new(group);
    nizk_dl_eq_proof dec_pi;
    dec_share = dh_pvss_decrypt_share_prove(group, first_dist_kp.pub, &committee_key_pairs[0], encrypted_shares[0], &dec_pi, ctx);
    end = platform_utils_get_wall_time();
    double time_dec_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("decrypting a single share: %f seconds\n", time_dec_elapsed);
      fflush(stdout);
    }

    /* verify decryption of single encrypted share */
    start = platform_utils_get_wall_time();
    ret += dh_pvss_decrypt_share_verify(group, first_dist_kp.pub, committee_public_keys[0], encrypted_shares[0], dec_share, &dec_pi, ctx);
    end = platform_utils_get_wall_time();
    double time_verdec_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("verify decryption of single encrypted share: %f seconds\n", time_verdec_elapsed);
      fflush(stdout);
    }

    // cleanup
    nizk_dl_eq_proof_free(&dec_pi);
    point_free(dec_share);

    /* preparation for reconstruction test: decrypting the encrypted shares and verifiying */
    if (verbose) {
        printf("Simulating decryption for %d devices in preparation for reconstructing secret\n",t+1);
        fflush(stdout);
    }
    EC_POINT *decrypted_shares[t+1];
    for (int i=0; i<t+1; i++) {

        nizk_dl_eq_proof committee_member_pi;
        decrypted_shares[i] = dh_pvss_decrypt_share_prove(group, first_dist_kp.pub, &committee_key_pairs[i], encrypted_shares[i], &committee_member_pi, ctx);

        // cleanup
        nizk_dl_eq_proof_free(&committee_member_pi);

    }

    /* reconstruct secret */
    start = platform_utils_get_wall_time();
    EC_POINT *reconstruction_shares[t+1];
    int reconstruction_indices[t+1];
    int first = 0;
    for (int i=first; i<first+t+1; i++) {
        reconstruction_shares[i-first] = decrypted_shares[i];
        int pp_alpha_as_int = (int)BN_get_word(pp.alphas[i+1]); // this works since alphas were chosen small enough to fit in an int
        reconstruction_indices[i-first] = pp_alpha_as_int;
    }
    EC_POINT *reconstructed_secret = dh_pvss_reconstruct(group, (const EC_POINT**)reconstruction_shares, reconstruction_indices, pp.t, t+1, ctx);
    end = platform_utils_get_wall_time();
    double time_rec_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("reconstructing secret: %f seconds\n", time_rec_elapsed);
      fflush(stdout);
    }
    ret += point_cmp(group, secret, reconstructed_secret, ctx);

    /* setup for next epoch committee */
    if (verbose) {
        printf("Performing setup and generating keys for next epoch committee...");
        fflush(stdout);
    }
    dh_pvss_ctx next_pp;
    dh_pvss_setup(&next_pp, group, t, n, ctx);
    // keygen for next epoch committe
    dh_key_pair next_committee_key_pairs[n];
    EC_POINT *next_committee_public_keys[n];
    for (int i=0; i<next_pp.n; i++) {
        dh_key_pair *next_com_member_key_pair = &next_committee_key_pairs[i];
        dh_key_pair_generate(group, next_com_member_key_pair, ctx);
        next_committee_public_keys[i] = next_com_member_key_pair->pub;
    }
    if (verbose) {
        printf("done\n");
        fflush(stdout);
    }

    /* make a single reshare */
    start = platform_utils_get_wall_time();
    int party_index = 3;
    EC_POINT *encrypted_re_shares[next_pp.n];
    nizk_reshare_proof reshare_pi;
    dh_pvss_reshare_prove(group, party_index, &committee_key_pairs[party_index], &dist_key_pairs[party_index], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, pp.n, &next_pp, (const EC_POINT**)next_committee_public_keys, encrypted_re_shares, &reshare_pi, ctx);
    end = platform_utils_get_wall_time();
    double time_reshare_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("reshare (one party): %f seconds\n", time_reshare_elapsed);
      fflush(stdout);
    }

    /* verify reshare */
    start = platform_utils_get_wall_time();
    ret += dh_pvss_reshare_verify(&pp, &next_pp, party_index, committee_public_keys[party_index], dist_public_keys[party_index], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, (const EC_POINT**)next_committee_public_keys, encrypted_re_shares, &reshare_pi);
    end = platform_utils_get_wall_time();
    double time_reshare_verify_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("verify (one) reshare: %f seconds\n", time_reshare_verify_elapsed);
      fflush(stdout);
    }

    // the below will make a full reshare -> and the reconstruct a single of those shares

    // 1. preparation: make a reshare for all parties (this essentially simulates t+1 resharings on the device, which will take a while for large t. This time is not included in the measurements)


    EC_POINT **all_encrypted_re_shares[pp.t+1];

    for (int i=0; i<pp.t+1; i++) {
        all_encrypted_re_shares[i] = malloc(sizeof(EC_POINT *[next_pp.n]));
        assert(all_encrypted_re_shares[i] && "bad allocation for all_encrypted_re_shares");
    }

    if (verbose) {
        printf("Simulating resharing for %d devices in preparation for reconstructing reshare, this might take a while\n",t+1);
        fflush(stdout);
    }

    nizk_reshare_proof reshare_pis[pp.n];
    for (int i=0; i<pp.t+1; i++) {
        if (verbose && (i % 100 == 0)) {
            printf("progress: %d of %d\n",i,t+1);
            fflush(stdout);
        }
        dh_pvss_reshare_prove(group, i, &committee_key_pairs[i], &dist_key_pairs[i], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, pp.n, &next_pp, (const EC_POINT**)next_committee_public_keys, all_encrypted_re_shares[i], &reshare_pis[i], ctx);
    }

    // 2. reconstruct reshare
    double time_device_reshare_reconstruct_elapsed = 0;
    start = platform_utils_get_wall_time();
    int valid_indices[pp.t+1];
    for (int i=0; i<pp.t+1; i++) {
        valid_indices[i] = i+1; // all indices are valid for this test
    }

    EC_POINT *reconstructed_encrypted_reshare;
    EC_POINT *slice_of_encrypted_reshares[next_pp.t+1];
    for (int i=0; i<next_pp.t+1; i++) {
        slice_of_encrypted_reshares[i] = all_encrypted_re_shares[ valid_indices[i] - 1 ][0];// get the the 0:th share from k+1 rehares
    }
    reconstructed_encrypted_reshare = dh_pvss_reconstruct_reshare(&pp, next_pp.t+1, valid_indices, slice_of_encrypted_reshares);
    end = platform_utils_get_wall_time();
    time_device_reshare_reconstruct_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("reconstruct (encrypted) reshare (one party): %f seconds\n", time_device_reshare_reconstruct_elapsed);
      fflush(stdout);
    }

    //measure the max RAM memory footprint of the current process
    uint64_t max_ram_footprint = platform_utils_get_max_memory_usage();
    if (verbose) {
      printf("memory footprint: %" PRIu64 " bytes\n\n", max_ram_footprint);
      fflush(stdout);
    }

    // cleanup
    BN_CTX_free(ctx);
    point_free(secret);
    dh_key_pair_free(&first_dist_kp);
    for (int i=0; i<n; i++){
        dh_key_pair_free(&committee_key_pairs[i]);
        dh_key_pair_free(&dist_key_pairs[i]);
        point_free(encrypted_shares[i]);
    }
    for (int i = 0; i<pp.t+1; i++) {
        point_free(decrypted_shares[i]);
    }
    for (int i=0; i<n; i++){
        dh_key_pair_free(&next_committee_key_pairs[i]);
    }
    nizk_dl_eq_proof_free(&distribution_pi);
    point_free(reconstructed_secret);
    for (int i=0; i<next_pp.n; i++){
        point_free(encrypted_re_shares[i]);
    }
    nizk_reshare_proof_free(&reshare_pi);
    for (int j = 0; j<next_pp.n; j++) {
        for (int i = 0; i<pp.t+1; i++) { // get the the j:th share from all n rehares
            point_free(all_encrypted_re_shares[i][j]);
        }
    }
    for (int i = 0; i<pp.t+1; i++) {
        free(all_encrypted_re_shares[i]);
    }
    for (int i=0; i<pp.t+1; i++){
        nizk_reshare_proof_free(&reshare_pis[i]);
    }
    point_free(reconstructed_encrypted_reshare);

    dh_pvss_ctx_free(&pp);
    dh_pvss_ctx_free(&next_pp);

    if (results) {
      results[0] = time_setup_and_keygen;
      results[1] = time_dist_elapsed;
      results[2] = time_dist_verify_elapsed;
      results[3] = time_dec_elapsed;
      results[4] = time_verdec_elapsed;
      results[5] = time_rec_elapsed;
      results[6] = time_reshare_elapsed;
      results[7] = time_reshare_verify_elapsed;
      results[8] = time_device_reshare_reconstruct_elapsed;
      results[9] = (double)max_ram_footprint;
    }

#ifdef DEBUG
    print_allocation_status();
#endif
    return ret;
}

/* faster performance test than the above, since the correctness part of the test is skipped here */
int performance_test(double *results, int t, int n, int verbose) {

    int ret = 0;

    if (verbose) {
        printf("Running performance test with (n, t) = (%d, %d)\n", n, t);
    }

    /* setup & keygen */
    // setup
    if (verbose) {
      printf("setup & keygen: ");
      fflush(stdout);
    }
    platform_time_type start = platform_utils_get_wall_time();
    const EC_GROUP *group = get0_group();
    BN_CTX *ctx = BN_CTX_new();
    dh_pvss_ctx pp;
    dh_pvss_setup(&pp, group, t, n, ctx);
    EC_POINT *secret = point_random(group, ctx);

    // keygen
    dh_key_pair first_dist_kp;
    dh_key_pair_generate(group, &first_dist_kp, ctx);
    dh_key_pair committee_key_pairs[n];
    dh_key_pair dist_key_pairs[n];
    EC_POINT **committee_public_keys = malloc(sizeof(EC_POINT*) * n);
    EC_POINT **dist_public_keys = malloc(sizeof(EC_POINT*) * n);
    for (int i=0; i<n; i++) {
        dh_key_pair *com_member_key_pair = &committee_key_pairs[i];
        dh_key_pair *dist_key_pair = &dist_key_pairs[i];
        dh_key_pair_generate(group, com_member_key_pair, ctx);
        dh_key_pair_generate(group, dist_key_pair, ctx);
        committee_public_keys[i] = com_member_key_pair->pub;
        dist_public_keys[i] = dist_key_pair->pub;
    }
    platform_time_type end = platform_utils_get_wall_time();
    double time_setup_and_keygen = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("%f seconds\n", time_setup_and_keygen);
      fflush(stdout);
    }

    /* distribution phase (make encrypted shares with proofs) */
    if (verbose) {
      printf("distribute: ");
      fflush(stdout);
    }
    EC_POINT **encrypted_shares = malloc(sizeof(EC_POINT*) * n);
    nizk_dl_eq_proof distribution_pi;
    start = platform_utils_get_wall_time();
    dh_pvss_distribute_prove(&pp, encrypted_shares, &first_dist_kp, (const EC_POINT**)committee_public_keys, secret, &distribution_pi);
    end = platform_utils_get_wall_time();
    double time_dist_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("%f seconds\n", time_dist_elapsed);
      fflush(stdout);
    }

    /* verifying encrypted shares */
    if (verbose) {
      printf("verify distribution: ");
      fflush(stdout);
    }
    start = platform_utils_get_wall_time();
    ret += dh_pvss_distribute_verify(&pp, &distribution_pi, (const EC_POINT**)encrypted_shares, first_dist_kp.pub, (const EC_POINT**)committee_public_keys);
    end = platform_utils_get_wall_time();
    double time_dist_verify_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("%f seconds\n", time_dist_verify_elapsed);
      fflush(stdout);
    }

    /* decrypt a single share */
    if (verbose) {
      printf("decrypting a single share: ");
      fflush(stdout);
    }
    nizk_dl_eq_proof dec_pi;
    start = platform_utils_get_wall_time();
    EC_POINT *dec_share = dh_pvss_decrypt_share_prove(group, first_dist_kp.pub, &committee_key_pairs[0], encrypted_shares[0], &dec_pi, ctx);
    end = platform_utils_get_wall_time();
    double time_dec_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("%f seconds\n", time_dec_elapsed);
      fflush(stdout);
    }

    /* verify decryption of single encrypted share */
    if (verbose) {
      printf("verify decryption of single encrypted share: ");
      fflush(stdout);
    }
    start = platform_utils_get_wall_time();
    ret += dh_pvss_decrypt_share_verify(group, first_dist_kp.pub, committee_public_keys[0], encrypted_shares[0], dec_share, &dec_pi, ctx);
    end = platform_utils_get_wall_time();
    double time_verdec_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("%f seconds\n", time_verdec_elapsed);
      fflush(stdout);
    }

    // cleanup
    nizk_dl_eq_proof_free(&dec_pi);
    point_free(dec_share);

    /* preparation for reconstruction test: decrypting the encrypted shares and verifiying */
    if (verbose) {
        printf("Simulating decryption for %d devices in preparation for reconstructing secret\n",t+1);
        fflush(stdout);
    }
    EC_POINT **decrypted_shares = malloc(sizeof(EC_POINT*) * (t+1));
    for (int i=0; i<t+1; i++) {

        nizk_dl_eq_proof committee_member_pi;
        decrypted_shares[i] = dh_pvss_decrypt_share_prove(group, first_dist_kp.pub, &committee_key_pairs[i], encrypted_shares[i], &committee_member_pi, ctx);

        // cleanup
        nizk_dl_eq_proof_free(&committee_member_pi);
    }

    /* reconstruct secret */
    if (verbose) {
      printf("reconstructing secret: ");
      fflush(stdout);
    }
    EC_POINT **reconstruction_shares = malloc(sizeof(EC_POINT*) * (t+1));
    int reconstruction_indices[t+1];
    int first = 0;
    for (int i=first; i<first+t+1; i++) {
        reconstruction_shares[i-first] = decrypted_shares[i];
        int pp_alpha_as_int = (int)BN_get_word(pp.alphas[i+1]); // this works since alphas were chosen small enough to fit in an int
        reconstruction_indices[i-first] = pp_alpha_as_int;
    }
    start = platform_utils_get_wall_time();
    EC_POINT *reconstructed_secret = dh_pvss_reconstruct(group, (const EC_POINT**)reconstruction_shares, reconstruction_indices, pp.t, t+1, ctx);
    end = platform_utils_get_wall_time();
    double time_rec_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("%f seconds\n", time_rec_elapsed);
      fflush(stdout);
    }
    ret += point_cmp(group, secret, reconstructed_secret, ctx);

    /* setup for next epoch committee */
    if (verbose) {
        printf("Performing setup and generating keys for next epoch committee");
        fflush(stdout);
    }
    dh_pvss_ctx next_pp;
    dh_pvss_ctx_copy(&next_pp, &pp, pp.t);
    // keygen for next epoch committe
    dh_key_pair next_committee_key_pairs[next_pp.n];
    EC_POINT **next_committee_public_keys = malloc(sizeof(EC_POINT*) * next_pp.n);
    for (int i=0; i<next_pp.n; i++) {
        dh_key_pair *next_com_member_key_pair = &next_committee_key_pairs[i];
        dh_key_pair_generate(group, next_com_member_key_pair, ctx);
        next_committee_public_keys[i] = next_com_member_key_pair->pub;
        if (verbose) {
          if (i % 1000 == 0) {
            printf(".");
            fflush(stdout);
          }
        }
    }
    if (verbose) {
      printf(", done\n");
      fflush(stdout);
    }

    /* make a single reshare */
    if (verbose) {
      printf("reshare (one party): ");
      fflush(stdout);
    }
    int party_index = 3;
    EC_POINT **encrypted_re_shares = malloc(sizeof(EC_POINT *) * next_pp.n);
    nizk_reshare_proof reshare_pi;
    start = platform_utils_get_wall_time();
    dh_pvss_reshare_prove(group, party_index, &committee_key_pairs[party_index], &dist_key_pairs[party_index], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, pp.n, &next_pp, (const EC_POINT**)next_committee_public_keys, encrypted_re_shares, &reshare_pi, ctx);
    end = platform_utils_get_wall_time();
    double time_reshare_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("%f seconds\n", time_reshare_elapsed);
      fflush(stdout);
    }

    /* verify reshare */
    if (verbose) {
      printf("verify (one) reshare: ");
      fflush(stdout);
    }
    start = platform_utils_get_wall_time();
    ret += dh_pvss_reshare_verify(&pp, &next_pp, party_index, committee_public_keys[party_index], dist_public_keys[party_index], first_dist_kp.pub, (const EC_POINT**)encrypted_shares, (const EC_POINT**)next_committee_public_keys, encrypted_re_shares, &reshare_pi);
    end = platform_utils_get_wall_time();
    double time_reshare_verify_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("%f seconds\n", time_reshare_verify_elapsed);
      fflush(stdout);
    }

    /* full reconstruction omitted from code above*/
    /* the implementation is used for speed testing only, so we use random datsa points as input to avoid extensive setup time */

    /* reconstruct reshare */
    int valid_indices[pp.t+1];
    for (int i=0; i<pp.t+1; i++) {
        valid_indices[i] = i+1; // all indices are valid for this test
    }
    EC_POINT **slice_of_encrypted_reshares = malloc(sizeof(EC_POINT*) * (next_pp.t+1));
    for (int i=0; i<next_pp.t+1; i++) {
        slice_of_encrypted_reshares[i] = point_random(group, ctx); // just use random points for speed test
    }
    start = platform_utils_get_wall_time();
    EC_POINT *reconstructed_encrypted_reshare = dh_pvss_reconstruct_reshare(&pp, next_pp.t+1, valid_indices, slice_of_encrypted_reshares);
    end = platform_utils_get_wall_time();
    double time_device_reshare_reconstruct_elapsed = platform_utils_get_wall_time_diff(start, end);
    if (verbose) {
      printf("reconstruct (encrypted) share (one party): %f seconds\n", time_device_reshare_reconstruct_elapsed);
      fflush(stdout);
    }

    /* measure the max RAM memory footprint of the current process */
    uint64_t max_ram_footprint = platform_utils_get_max_memory_usage();
    if (verbose) {
      printf("memory footprint: %" PRIu64 " bytes\n\n", max_ram_footprint);
      fflush(stdout);
    }

    // cleanup
    BN_CTX_free(ctx);
    point_free(secret);
    free(next_committee_public_keys);
    free(reconstruction_shares);
    dh_key_pair_free(&first_dist_kp);
    for (int i=0; i<n; i++){
        dh_key_pair_free(&committee_key_pairs[i]);
        dh_key_pair_free(&dist_key_pairs[i]);
    }
    for (int i=0; i<n; i++){
        point_free(encrypted_shares[i]);
    }
    free(encrypted_shares);
    for (int i = 0; i<pp.t+1; i++) {
        point_free(decrypted_shares[i]);
    }
    free(decrypted_shares);
    for (int i=0; i<next_pp.n; i++){
        dh_key_pair_free(&next_committee_key_pairs[i]);
    }
    nizk_dl_eq_proof_free(&distribution_pi);
    point_free(reconstructed_secret);
    for (int i=0; i<next_pp.n; i++){
        point_free(encrypted_re_shares[i]);
    }
    free(encrypted_re_shares);
    nizk_reshare_proof_free(&reshare_pi);
    for (int i=0; i<next_pp.t+1; i++) {
        point_free(slice_of_encrypted_reshares[i]);
    }
    free(slice_of_encrypted_reshares);
    point_free(reconstructed_encrypted_reshare);

    free(committee_public_keys);
    free(dist_public_keys);

    dh_pvss_ctx_free(&pp);
    dh_pvss_ctx_free(&next_pp);

    if (results) {
      results[0] = time_setup_and_keygen;
      results[1] = time_dist_elapsed;
      results[2] = time_dist_verify_elapsed;
      results[3] = time_dec_elapsed;
      results[4] = time_verdec_elapsed;
      results[5] = time_rec_elapsed;
      results[6] = time_reshare_elapsed;
      results[7] = time_reshare_verify_elapsed;
      results[8] = time_device_reshare_reconstruct_elapsed;
      results[9] = (double)max_ram_footprint;
    }

#ifdef DEBUG
    print_allocation_status();
#endif
    return ret;
}
