//
//  P256.h
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-07.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#ifndef P256_h
#define P256_h

#include <stdio.h>
#include <openssl/bn.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#import <openssl/evp.h>

#endif /* P256_h */

// get curve group
EC_GROUP* getGroup(void);

// get curve group order p
const BIGNUM* get0Order(void);

// get curve group generator
EC_POINT* get0Gen(void);

// get random element in Zp
BIGNUM* randZp(void);

// helper to print bignum to terminal for debug
void printBN(const BIGNUM *x);

// multiply Point with int < p
EC_POINT* multiply(const EC_POINT* p, const BIGNUM *x);

// add points
EC_POINT* add(const EC_POINT* a, const EC_POINT* b);
