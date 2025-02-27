//
//  SSS.h
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-15.
//

#ifndef SSS_H
#define SSS_H
#include "P256.h"

// array of size n for resulting shares, the secret, and t and n
void shamir_shares_generate(const EC_GROUP *group, EC_POINT *shares[], const EC_POINT *secret, const int t, const int n, BN_CTX *ctx);
EC_POINT *shamir_shares_reconstruct(const EC_GROUP *group, const EC_POINT *shares[], const int shareIndexes[], const int t, const int length, BN_CTX *ctx);
int shamir_shares_test_suite(int print);

void lagX(const EC_GROUP *group, BIGNUM *prod, const int share_indexes[], int length, int i, BN_CTX *ctx);

#endif /* SSS_H */
