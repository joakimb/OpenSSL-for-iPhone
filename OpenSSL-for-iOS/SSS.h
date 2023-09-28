//
//  SSS.h
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-15.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#ifndef SSS_h
#define SSS_h
#include <stdio.h>
#include "P256.h"

// array of size n for resulting shares, the secret, and t and n
void shamir_shares_generate(EC_POINT **shares, EC_POINT *secret, const int t, const int n);
EC_POINT* shamir_shares_reconstruct(EC_POINT *shares[], int shareIndexes[], int t, int length);

int test_shamir_sharing(void);

#endif /* SSS_h */
