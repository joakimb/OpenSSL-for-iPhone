//
//  NIZK.c
//
//  Created by Paul Stankovski Wagner on 2023-09-19.
//

#include <stdio.h>
#include <assert.h>
#include "NIZK.h"
#include "openssl_hashing_tools.h"

/*
 *
 * nizk_dl
 *
 */

void nizk_dl_proof_free(nizk_dl_proof *pi) {
    assert(pi && "nizk_dl_proof_free: usage error, no proof passed");
    assert(pi->u && "nizk_dl_proof_free: usage error, u is NULL");
    assert(pi->z && "nizk_dl_proof_free: usage error, z is NULL");
    EC_POINT_free(pi->u);
    pi->u = NULL; // superflous safety
    BN_free(pi->z);
    pi->z = NULL; // superflous safety
}

void nizk_dl_prove(const EC_GROUP *group, const BIGNUM *x, nizk_dl_proof *pi, BN_CTX *ctx) {
    const BIGNUM *order = get0OrderFromGroup(group);
    const EC_POINT *generator = get0GeneratorFromGroup(group);

    // compute X
    EC_POINT *X = bn2point(group, x, ctx);

    // compute u
    BIGNUM *r = randZp(ctx);
    pi->u = bn2point(group, r, ctx);

    // compute c
    BIGNUM *c = openssl_hash_ppp2bn(group, generator, X, pi->u, ctx);

    // compute z
    pi->z = BN_new();
    int ret = BN_mod_mul(pi->z, c, x, order, ctx);
    assert(ret == 1 && "BN_mod_mul computation failed in nizk_dl_prove");
    ret = BN_mod_add(pi->z, pi->z, r, order, ctx);
    assert(ret == 1 && "BN_mod_add computation failed in nizk_dl_prove");

    // cleanup
    BN_free(c);
    BN_free(r);
    EC_POINT_free(X);
    /* implicitly return pi = (u, z) */
}

int nizk_dl_verify(const EC_GROUP *group, const EC_POINT *X, const nizk_dl_proof *pi, BN_CTX *ctx) {
    const EC_POINT *generator = get0GeneratorFromGroup(group);

    // compute Z
    EC_POINT *Z = bn2point(group, pi->z, ctx);

    // compute Z_prime
    EC_POINT *Z_prime = EC_POINT_new(group);

    BIGNUM *c = openssl_hash_ppp2bn(group, generator, X, pi->u, ctx);
    EC_POINT_mul(group, Z_prime, NULL, X, c, ctx);
    EC_POINT_add(group, Z_prime, Z_prime, pi->u, ctx);
    
    // Z == Z_prime ?
    int ret = EC_POINT_cmp(group, Z, Z_prime, ctx);

    // cleanup
    BN_free(c);
    EC_POINT_free(Z_prime);
    EC_POINT_free(Z);

    return ret;
}

/*
 *
 * nizk_dl_eq
 *
 */

void nizk_dl_eq_proof_free(nizk_dl_eq_proof *pi) {
    assert(pi && "nizk_dl_eq_proof_free: usage error, no proof passed");
    assert(pi->Ra && "nizk_dl_eq_proof_free: usage error, Ra is NULL");
    assert(pi->Rb && "nizk_dl_eq_proof_free: usage error, Rb is NULL");
    assert(pi->z && "nizk_dl_eq_proof_free: usage error, z is NULL");
    EC_POINT_free(pi->Ra);
    pi->Ra = NULL; // superflous safety
    EC_POINT_free(pi->Rb);
    pi->Rb = NULL; // superflous safety
    BN_free(pi->z);
    pi->z = NULL; // superflous safety
}

void nizk_dl_eq_prove(const EC_GROUP *group, const BIGNUM *exp, const EC_POINT *a, const EC_POINT *A, const EC_POINT *b, const EC_POINT *B, nizk_dl_eq_proof *pi, BN_CTX *ctx) {
    const BIGNUM *order = get0OrderFromGroup(group);

    // compute Ra
    BIGNUM *r = randZp(ctx); // draw r uniformly at random
    pi->Ra = EC_POINT_new(group);
    EC_POINT_mul(group, pi->Ra, NULL, a, r, ctx);

    // compute Rb
    pi->Rb = EC_POINT_new(group);
    EC_POINT_mul(group, pi->Rb, NULL, b, r, ctx);

    // compute c
    BIGNUM *c = openssl_hash_pppppp2bn(group, a, A, b, B, pi->Ra, pi->Rb, ctx);

    // compute z
    pi->z = BN_new();
    int ret = BN_mod_mul(pi->z, c, exp, order, ctx);
    assert(ret == 1 && "nizk_dl_eq_prove: BN_mod_mul computation failed");
    ret = BN_mod_sub(pi->z, r, pi->z, order, ctx);
    assert(ret == 1 && "nizk_dl_eq_prove: BN_mod_sub computation failed");

    // cleanup
    BN_free(c);
    BN_free(r);
    /* implicitly return pi = (Ra, Rb, z) */
}

int nizk_dl_eq_verify(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *A, const EC_POINT *b, const EC_POINT *B, const nizk_dl_eq_proof *pi, BN_CTX *ctx) {
    // compute c
    BIGNUM *c = openssl_hash_pppppp2bn(group, a, A, b, B, pi->Ra, pi->Rb, ctx);

    /* check if pi->Ra = [pi->z]a + [c]A */
    EC_POINT *Ra_prime = EC_POINT_new(group);
    const EC_POINT *a_points[] = { a, A };
    const BIGNUM *bns[] = { pi->z, c };
    EC_POINTs_mul(group, Ra_prime, NULL, 2, a_points, bns, ctx);
    int ret = EC_POINT_cmp(group, Ra_prime, pi->Ra, ctx);
    assert(ret != -1 && "nizk_dl_eq_verify: error in EC_POINT_cmp(Ra_prime, Ra)");
    EC_POINT_free(Ra_prime);
    if (ret == 1) { // not equal
        BN_free(c);
        return 1; // verification failed
    }

    /* check if pi->Rb = [pi->z]b + [c]B */
    EC_POINT *Rb_prime = EC_POINT_new(group);
    const EC_POINT *b_points[] = { b, B };
    EC_POINTs_mul(group, Rb_prime, NULL, 2, b_points, bns, ctx);
    ret = EC_POINT_cmp(group, Rb_prime, pi->Rb, ctx);
    assert(ret != -1 && "nizk_dl_eq_verify: error in EC_POINT_cmp(Rb_prime, Rb)");
    EC_POINT_free(Rb_prime);
    if (ret == 1) { // not equal
        BN_free(c);
        return 1; // verification failed
    }

    // cleanup
    BN_free(c);

    return 0; // verification successful
}



/*
 *
 *  nizk_dl tests
 *
 */

static int nizk_dl_test_1(int print) {
    const EC_GROUP *group = get0Group();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *seven = BN_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = EC_POINT_new(group);
    EC_POINT_mul(group, secret, seven, NULL, NULL, ctx);
    if (print) {
        printf("secret:\n");
        printPoint(secret, ctx);
    }
    
    // test 1: produce correct proof and verify
    nizk_dl_proof pi;
    nizk_dl_prove(group, seven, &pi, ctx);
    int ret1 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        printf("Test 1 %s: Correct NIZK DL Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // cleanup
    nizk_dl_proof_free(&pi);
    EC_POINT_free(secret);
    BN_free(seven);
    BN_CTX_free(ctx);

    // return test results
    return ret1 != 0;
}

static int nizk_dl_test_2(int print) {
    const EC_GROUP *group = get0Group();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *seven = BN_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = EC_POINT_new(group);
    EC_POINT_mul(group, secret, seven, NULL, NULL, ctx);
    if (print) {
        printf("secret:\n");
        printPoint(secret, ctx);
    }

    // produce correct proof and verify
    nizk_dl_proof pi;
    nizk_dl_prove(group, seven, &pi, ctx);
    int ret1 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        printf("Test 2 part 1 %s: Correct NIZK DL Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // negative tests
    // try to verify incorrect proof (z-value wrong)
    BN_free(pi.z);
    pi.z = randZp(ctx); // omitted to check if new erroneous z-value is actually by chance the correct value
    int ret2 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        if (ret2) {
            printf("Test 2 part 2 OK: Incorrect NIZK DL Proof not accepted (which is CORRECT)\n");
        } else {
            printf("Test 2 part 2 NOT OK: Incorrect NIZK DL Proof IS accepted (which is an ERROR)\n");
        }
    }

    // cleanup
    nizk_dl_proof_free(&pi);
    EC_POINT_free(secret);
    BN_free(seven);
    BN_CTX_free(ctx);

    // return test results
    return !(ret1 == 0 && ret2 != 0);
}

static int nizk_dl_test_3(int print) {
    const EC_GROUP *group = get0Group();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *seven = BN_new();
    BN_dec2bn(&seven, "7");
    EC_POINT *secret = EC_POINT_new(group);
    EC_POINT_mul(group, secret, seven, NULL, NULL, ctx);
    if (print) {
        printf("secret:\n");
        printPoint(secret, ctx);
    }

    // produce correct proof and verify
    nizk_dl_proof pi;
    nizk_dl_prove(group, seven, &pi, ctx);
    int ret1 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        printf("Test 3 part 1 %s: Correct NIZK DL Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // negative tests
    // try to verify incorrect proof (both u- and z-value wrong)
    EC_POINT_free(pi.u);
    pi.u = randPoint(group, ctx);  // omitted to check if modified u-value actually by chance produces a valid proof
    int ret2 = nizk_dl_verify(group, secret, &pi, ctx);
    if (print) {
        if (ret2) {
            printf("Test 3 part 2 OK: Incorrect NIZK DL Proof not accepted (which is CORRECT)\n");
        } else {
            printf("Test 3 part 2 NOT OK: Incorrect NIZK DL Proof IS accepted (which is an ERROR)\n");
        }
    }

    // cleanup
    nizk_dl_proof_free(&pi);
    EC_POINT_free(secret);
    BN_free(seven);
    BN_CTX_free(ctx);

    // return test results
    return !(ret1 == 0 && ret2 != 0);
}

typedef int (*test_function)(int);

static test_function test_suite_dl[] = {
    &nizk_dl_test_1,
    &nizk_dl_test_2,
    &nizk_dl_test_3
};

// return test results
//   0 = passed (all individual tests passed)
//   1 = failed (one or more individual tests failed)
// setting print to 0 (zero) suppresses stdio printouts, while print 1 is 'verbose'
int nizk_dl_test_suite(int print) {
    int num_tests = sizeof(test_suite_dl)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite_dl[i](print)) {
            ret = 1;
        }
    }
    return ret;
}

/*
 *
 *  nizk_dl_eq tests
 *
 */
static int nizk_dl_eq_test_1(int print) {
    const EC_GROUP *group = get0Group();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *exp = BN_new();
    BN_dec2bn(&exp, "7");
    BIGNUM *exp_bad = BN_new();
    BN_dec2bn(&exp_bad, "6");

    EC_POINT *a = randPoint(group, ctx);
    EC_POINT *A = EC_POINT_new(group);
    EC_POINT_mul(group, A, NULL, a, exp, ctx);

    EC_POINT *b = randPoint(group, ctx);
    EC_POINT *B = EC_POINT_new(group);
    EC_POINT_mul(group, B, NULL, b, exp, ctx);

    // produce correct proof and verify
    nizk_dl_eq_proof pi;
    nizk_dl_eq_prove(group, exp, a, A, b, B, &pi, ctx);
    int ret1 = nizk_dl_eq_verify(group, a, A, b, B, &pi, ctx);
    if (print) {
        printf("Test 1 part 1 %s: Correct NIZK DL EQ Proof %s accepted\n", ret1 ? "NOT OK" : "OK", ret1 ? "NOT" : "indeed");
    }

    // negative tests
    // try to verify incorrect proof (bad B-value)
    EC_POINT *B_bad = EC_POINT_new(group);
    EC_POINT_mul(group, B_bad, NULL, b, exp_bad, ctx);
    int ret2 = nizk_dl_eq_verify(group, a, A, b, B_bad, &pi, ctx);
    if (print) {
        if (ret2) {
            printf("Test 1 part 2 OK: Incorrect NIZK DL EQ Proof not accepted (which is CORRECT)\n");
        } else {
            printf("Test 1 part 2 NOT OK: Incorrect NIZK DL EQ Proof IS accepted (which is an ERROR)\n");
        }
    }
    printf("ret1 = %d\nret2 = %d\n", ret1, ret2);

    // cleanup
    nizk_dl_eq_proof_free(&pi);
    EC_POINT_free(a);
    EC_POINT_free(A);
    EC_POINT_free(b);
    EC_POINT_free(B);
    EC_POINT_free(B_bad);
    BN_free(exp);
    BN_free(exp_bad);
    BN_CTX_free(ctx);

    // return test results
    return !(ret1 == 0 && ret2 != 0);
}

static test_function test_suite_dl_eq[] = {
    &nizk_dl_eq_test_1
};

int nizk_dl_eq_test_suite(int print) {
    int num_tests = sizeof(test_suite_dl_eq)/sizeof(test_function);
    int ret = 0;
    for (int i=0; i<num_tests; i++) {
        if (test_suite_dl_eq[i](print)) {
            ret = 1;
        }
    }
    return ret;
}


#if 0 // tests
//test chaum-pedersen fiat-shamir
print("CHAUM-PEDERSEN FS+++++++++++++++++++++++++++++++++")
let exp = BInt(5)
let a = try toPoint(randZp())
let b = try toPoint(randZp())
let A = try domain.multiplyPoint(a, exp)
let B = try domain.multiplyPoint(b, exp)
let Bad = try domain.multiplyPoint(b, BInt(6))
let pieq = try NIZKDLEQProve(exp: exp, a: a, A: A, b: b, B: B)
let valideq = try NIZKDLEQVerify(a: a, A: A, b: b, B: B, pi: pieq)
print("true dleq nizk:",valideq)
let invalideq = try NIZKDLEQVerify(a: a, A: A, b: b, B: Bad, pi: pieq)
print("false dleq nizk:",invalideq)#endif
#endif



#if 0
struct DLEQProof {
    var Ra: Point
    var Rb: Point
    var c: BInt
    var z: BInt
}

func NIZKDLEQProve(exp: BInt, a: Point, A: Point, b: Point, B: Point) throws -> DLEQProof {
    let r = randZp()
    let Ra = try domain.multiplyPoint(a, r)
    let Rb = try domain.multiplyPoint(b, r)
    let bytes = toBytes(a) + toBytes(A) + toBytes(b) + toBytes(B) + toBytes(Ra) + toBytes(Rb)
    let c = sha256(bytes).mod(domain.order)
    let z = r - c * exp.mod(domain.order)
    return DLEQProof(Ra: Ra, Rb: Rb, c: c, z: z)
}

func NIZKDLEQVerify(a: Point, A: Point, b: Point, B: Point, pi: DLEQProof) throws -> Bool {
    
    let bytes = toBytes(a) + toBytes(A) + toBytes(b) + toBytes(B) + toBytes(pi.Ra) + toBytes(pi.Rb)
    let cprime = sha256(bytes).mod(domain.order)
    let fsCheck = (pi.c == cprime)
    
    let alhs = pi.Ra
    let arhs1 = try domain.multiplyPoint(a, pi.z)
    let arhs2 = try domain.multiplyPoint(A, pi.c)
    let arhs = try domain.addPoints(arhs1, arhs2)
    let blhs = pi.Rb
    let brhs1 = try domain.multiplyPoint(b, pi.z)
    let brhs2 = try domain.multiplyPoint(B, pi.c)
    let brhs = try domain.addPoints(brhs1, brhs2)
    let chaumPedersenCheckA = (alhs == arhs)
    let chaumPedersenCheckB = (blhs == brhs)
    
    return (fsCheck && chaumPedersenCheckA && chaumPedersenCheckB)

}
#endif
