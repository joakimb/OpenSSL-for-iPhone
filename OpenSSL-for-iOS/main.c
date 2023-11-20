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

static void test_suite_performance(void) {
//    int n[] = {10,50,100};
//    int t[] = { 5,25, 50};
    int n[] = {10,50,100,200,300,400,500,528,1000,2000,5000,10000};
    int t[] = { 5,25, 50,100,150,200,250,264, 500,1000,2500, 5000};
    const int num_tests = sizeof(n)/sizeof(int);
    printf("Testing performances for (n, t)\n");
    for (int i=0; i<num_tests; i++) {
      printf("  (%d, %d)\n", n[i], t[i]);
    }
    printf("\n");
    fflush(stdout);
    for (int i=0; i<num_tests; i++) {
        int ret = performance_test(NULL, t[i], n[i], 1 /* verbose */);
        printf("ret = %d\n\n", ret);
        fflush(stdout);
    }
}

int main() {
    //test_suite_correctness();
    test_suite_performance();
    return 0;
}
