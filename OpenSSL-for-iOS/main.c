#include <stdio.h>
#include <stdlib.h>
#include "nizk_dl.h"
#include "nizk_dl_eq.h"
#include "nizk_reshare.h"
#include "dh_pvss.h"

static void test_suite_correctness(void) {
    const int print = 1;
    nizk_dl_test_suite(print);
    nizk_dl_eq_test_suite(print);
    nizk_reshare_test_suite(print);
    dh_pvss_test_suite(print);
}

static void test_suite_performance(int include_correctness_test) {
    int n[] = {10,50,100,200,300,400,500,528};
    int t[] = { 5,25, 50,100,150,200,250,264};
    //int n[] = {10,50,100,200,300,400,500,528,1000,2000,5000,10000,20000,50000,100000,200000,500000,1000000};
    //int t[] = { 5,25, 50,100,150,200,250,264, 500,1000,2500, 5000,10000,25000, 50000,100000,250000, 500000};
    //int n[] = {20000,50000,100000,200000,500000,1000000};
    //int t[] = {10000,25000, 50000,100000,250000, 500000};
    double timing_results[10];
    double reshare_time[sizeof(n)/sizeof(n[0])];
    const int num_tests = sizeof(n)/sizeof(int);
    printf("Testing performances for (n, t)\n");
    for (int i=0; i<num_tests; i++) {
      printf("  (%d, %d)\n", n[i], t[i]);
    }
    printf("\n");
    fflush(stdout);
    for (int i=0; i<num_tests; i++) {
        int ret;
        if (include_correctness_test) {
          ret = performance_test_with_correctness(timing_results, t[i], n[i], 1 /* verbose */);
        } else {
          ret = performance_test(timing_results, t[i], n[i], 1 /* verbose */);
        }
        reshare_time[i] = timing_results[6]; // get per-device timing result for resharing
        printf("ret = %d\nint committee_size[] = { %d", ret, n[0]);
        for (int j=1; j<i+1; j++) {
          printf(", %d", n[j]);
        }
        printf("};\ndouble reshare_time_in_seconds_per_device[] = { %f", reshare_time[0]);
        for (int j=1; j<i+1; j++) {
          printf(", %f", reshare_time[j]);
        }
        printf("};\n\n");
        fflush(stdout);
    }
}

int main() {
    //test_suite_correctness();
    test_suite_performance(0);
    return 0;
}
