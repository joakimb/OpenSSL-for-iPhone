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

static void print_committee_size_vector(int len, int *v) {
    printf("int                 committee_size[] = { %6d", v[0]);
    for (int j=1; j<len; j++) {
        printf(", %6d", v[j]);
    }
    printf("};\n");
    fflush(stdout);
}

static void print_timing_vector(const char *name, const char *unit, int len, double *v) {
    printf("double %27s[] = { %6.2f", name, v[0]);
    for (int j=1; j<len; j++) {
        printf(", %6.2f", v[j]);
    }
    printf("};\n");
    fflush(stdout);
}

static void test_suite_performance(int include_correctness_test) {
    int n[] = {10,20,50,100,200,300,400,500,528,750,1000,2000,3000,4000,5000,7500,10000,15000,20000};
    int t[] = { 5,10,25, 50,100,150,200,250,264,375, 500,1000,1500,2000,2500,3750, 5000, 7500,10000};
    double timing_results[10];
    double setup_and_keygen_time[sizeof(n)/sizeof(n[0])];
    double distribution_time[sizeof(n)/sizeof(n[0])];
    double verify_distribution_time[sizeof(n)/sizeof(n[0])];
    double decrypt_share_time[sizeof(n)/sizeof(n[0])];
    double verify_decrypted_share_time[sizeof(n)/sizeof(n[0])];
    double reconstruct_secret_time[sizeof(n)/sizeof(n[0])];
    double reshare_time[sizeof(n)/sizeof(n[0])];
    double verify_reshare_time[sizeof(n)/sizeof(n[0])];
    double share_reconstruction_time[sizeof(n)/sizeof(n[0])];
    double max_footprint[sizeof(n)/sizeof(n[0])];
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
        setup_and_keygen_time[i] = timing_results[0];
        distribution_time[i] = timing_results[1];
        verify_distribution_time[i] = timing_results[2];
        decrypt_share_time[i] = timing_results[3];
        verify_decrypted_share_time[i] = timing_results[4];
        reconstruct_secret_time[i] = timing_results[5];
        reshare_time[i] = timing_results[6];
        verify_reshare_time[i] = timing_results[7];
        share_reconstruction_time[i] = timing_results[8];
        max_footprint[i] = timing_results[9];

        printf("ret = %d\n", ret);
        print_committee_size_vector(i+1, n);
        print_timing_vector("setup_and_keygen_time", "seconds", i+1, setup_and_keygen_time);
        print_timing_vector("distribution_time", "seconds", i+1, distribution_time);
        print_timing_vector("verify_distribution_time", "seconds", i+1, verify_distribution_time);
        print_timing_vector("decrypt_share_time", "seconds", i+1, decrypt_share_time);
        print_timing_vector("verify_decrypted_share_time", "seconds", i+1, verify_decrypted_share_time);
        print_timing_vector("reconstruct_secret_time", "seconds", i+1, reconstruct_secret_time);
        print_timing_vector("reshare_time", "seconds", i+1, reshare_time);
        print_timing_vector("verify_reshare_time", "seconds", i+1, verify_reshare_time);
        print_timing_vector("share_reconstruction_time", "seconds", i+1, share_reconstruction_time);
        print_timing_vector("max_footprint", "bytes", i+1, max_footprint);
        printf("\n\n");
    }
}

int main() {
    //test_suite_correctness();
    test_suite_performance(0);
    return 0;
}
