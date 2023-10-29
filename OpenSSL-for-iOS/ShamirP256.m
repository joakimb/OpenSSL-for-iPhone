//
//  P256.m
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-05.
//

#import "ShamirP256.h"

@implementation ShamirP256

+ (void) print: (BIGNUM *) x {
    bn_print(x);
}

void speedTest(int t, int n) {
    double speeds[8];
    NSLog(@"Running speed test with t= %d, n=%d",t,n);
    int good_test = speed_test(speeds, t, n);
    NSString *speed_test_string = [NSMutableString stringWithString:@"\nSPEED RESULTS:\n"];
    
    NSString *s = [[NSString alloc] initWithFormat:@"(good_test = %d):\n",good_test];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"t: %d, n: %d\n",t,n];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"distribute: %f seconds\n",speeds[0]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"verify distribution: %f seconds\n",speeds[1]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"decrypt share: %f seconds\n",speeds[2]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"verify decryption of share: %f seconds\n",speeds[3]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"reconstruct: %f seconds\n",speeds[4]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"reshare (one party): %f seconds\n",speeds[5]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"verify (one) reshare: %f seconds\n",speeds[6]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"reconstruct (encrypted) reshare (one party): %f seconds\n",speeds[7]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    NSLog(@"%@",speed_test_string);
}

+ (NSString *)test:(NSString *) string {
    
    clock_t start_time_total = clock();
    
    int ret = 0;
    ret += shamir_shares_test_suite(1);
    ret += nizk_dl_test_suite(1);
    ret += nizk_dl_eq_test_suite(1);
    ret += nizk_reshare_test_suite(1);
    ret += dh_pvss_test_suite(1);
    
    clock_t end_time_total = clock();
    double elapsed_time_total = (double)(end_time_total - start_time_total) / CLOCKS_PER_SEC;
    
    NSString *formattedString = [[NSString alloc] initWithFormat:@"Test suite %s, Time: %f seconds\n", ret ? "NOT OK" : "OK", elapsed_time_total];
    
    NSLog(@"%@",formattedString);

    int speed_test_on = 1;
    if (speed_test_on) {
//        speedTest(5, 10);
//        speedTest(50, 100);
//        speedTest(100, 200);
//        speedTest(200, 400);
//        speedTest(250, 500);
        speedTest(264, 528);
    }
    
    return formattedString;
}


@end
