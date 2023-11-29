//
//  P256.m
//  OpenSSL-for-iOS
//
//  Created by Joakim Brorsson on 2023-09-05.
//

#import "PVSSWrapper.h"
#import <pthread.h>

struct TestParams {
    int t;
    int n;
};

@implementation PVSSWrapper


void* threadPerformanceTest(void* arg) {
    
    struct TestParams* args = (struct TestParams*)arg;
    int t = args->t;
    int n = args->n;

    double results[10];
    NSLog(@"Running performance test with t= %d, n=%d",t,n);
    int good_test = performance_test(results, t, n, 0 /* not verbose */);
    NSString *speed_test_string = [NSMutableString stringWithString:@"\nSPEED RESULTS:\n"];
    
    NSString *s = [[NSString alloc] initWithFormat:@"(good_test = %d):\n",good_test];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"t: %d, n: %d\n",t,n];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"setup and keygen: %f seconds\n",results[0]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"distribute: %f seconds\n",results[1]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"verify distribution: %f seconds\n",results[2]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"decrypt share: %f seconds\n",results[3]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"verify decryption of share: %f seconds\n",results[4]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"reconstruct: %f seconds\n",results[5]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"reshare (one party): %f seconds\n",results[6]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"verify (one) reshare: %f seconds\n",results[7]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"reconstruct (encrypted) reshare (one party): %f seconds\n",results[8]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    s = [[NSString alloc] initWithFormat:@"memory footprint: %f bytes\n",results[9]];
    speed_test_string = [speed_test_string stringByAppendingString:s];
    
    NSLog(@"%@",speed_test_string);
    
    pthread_exit(NULL);
}

+ (void) performanceTest{
    
    struct TestParams testParams[9];
    testParams[0].t = 5;
    testParams[0].n = 10;
    testParams[1].t = 50;
    testParams[1].n = 100;
    testParams[2].t = 100;
    testParams[2].n = 200;
    testParams[3].t = 200;
    testParams[3].n = 400;
    testParams[4].t = 250;
    testParams[4].n = 500;
    testParams[5].t = 264;
    testParams[5].n = 528;
    testParams[6].t = 500;
    testParams[6].n = 1000;
    testParams[7].t = 1000;
    testParams[7].n = 2000;

    for (int i = 0; i < 8; i++){
        
        //running each test in a new thread to separate memory measurements
        pthread_t thread;
        int result = pthread_create(&thread, NULL, threadPerformanceTest, &testParams[i]);
        if (result != 0) {
            NSLog(@"Failed to create thread: %s", strerror(result));
        }
        // Wait for tests to finish before starting a new one
        pthread_join(thread, NULL);

    }
}

+ (NSString *)functionalityTest:(NSString *) string {
    
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
    
    
    return formattedString;
}


@end
