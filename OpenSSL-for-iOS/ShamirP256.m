//
//  P256.m
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-05.
//  Copyright © 2023 Felix Schulze. All rights reserved.
//

#import "ShamirP256.h"


@implementation ShamirP256

+ (void) print: (BIGNUM *) x {
    print_bn(x);
}



+ (NSString *)test:(NSString *) string {
    
    clock_t start_time_total = clock();

    int ret = shamir_shares_test_suite(1);
//    int ret = nizk_dl_test_suite(1);
//    int ret = nizk_dl_eq_test_suite(1);
    
    clock_t end_time_total = clock();
    double elapsed_time_total = (double)(end_time_total - start_time_total) / CLOCKS_PER_SEC;
    
    NSString *formattedString = [[NSString alloc] initWithFormat:@"Test suite %s, Time: %f seconds\n", ret ? "NOT OK" : "OK", elapsed_time_total];
    NSLog(formattedString);

    return @"";
}


@end
