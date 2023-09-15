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

#endif /* SSS_h */
//array of size n for resulting shares, the secret, and t and n
void genShamirShares(EC_POINT **shares, EC_POINT *secret, const int t, const int n);
