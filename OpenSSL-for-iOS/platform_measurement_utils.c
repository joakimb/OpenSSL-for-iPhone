#include "platform_measurement_utils.h"

#if PLATFORM_TYPE == PLATFORM_TYPE_MAC
#include <mach/mach_time.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
//#include <mach/task_info.h>
//#include <mach/vm_statistics.h>
#include <unistd.h>
#if __has_include(<libproc.h>)
#include <libproc.h> // MacOS
#else
#include <sys/resource.h> // iOS, iPadOS, tvOS
int proc_pid_rusage(int pid, int flavor, rusage_info_t *buffer)
    __OSX_AVAILABLE_STARTING(__MAC_10_9, __IPHONE_7_0);
#endif
#endif

#if PLATFORM_TYPE == PLATFORM_TYPE_UNIX
#include <time.h>
#include <sys/time.h>
#endif

platform_time_type platform_utils_get_wall_time(void) {
#if PLATFORM_TYPE == PLATFORM_TYPE_MAC
    return mach_absolute_time();
#elif PLATFORM_TYPE == PLATFORM_TYPE_UNIX
    struct timeval t;
    if (gettimeofday(&t, NULL)) {
        return -1; // error, could not get time
    }
    return (double)t.tv_sec + (double)t.tv_usec * .000001;
#elif PLATFORM_TYPE == PLATFORM_TYPE_WINDOWS
  return clock();
#else
#error "unsupported platform type (not implemented for this platform)"
#endif
}

double platform_utils_get_wall_time_diff(platform_time_type start_time, platform_time_type end_time) {
#if PLATFORM_TYPE == PLATFORM_TYPE_MAC
    mach_timebase_info_data_t info;
    mach_timebase_info(&info);
    return (double)(end_time - start_time) * (double)info.numer / (double)info.denom / 1e9;
#elif PLATFORM_TYPE == PLATFORM_TYPE_UNIX
    return end_time - start_time;
#elif PLATFORM_TYPE == PLATFORM_TYPE_WINDOWS
  return (double)(end_time - start_time) / CLOCKS_PER_SEC;
#else
#error "unsupported platform type (not implemented for this platform)"
#endif
}

// measure the max RAM memory footprint of the current process
uint64_t platform_utils_get_max_memory_usage(void) {
#if PLATFORM_TYPE == PLATFORM_TYPE_MAC
#if 1
  rusage_info_current rusage_payload;
  int ret = proc_pid_rusage(getpid(),
                            RUSAGE_INFO_CURRENT,
                            (rusage_info_t *)&rusage_payload);
  if (ret != 0) { // error, could not retrieve rusage
    return 0;
  }
//  return rusage_payload.ri_phys_footprint;
  return rusage_payload.ri_lifetime_max_phys_footprint;
#else
  task_vm_info_data_t vm_info;
  mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
  if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vm_info, &count) != KERN_SUCCESS) {
      return 0; // failed to get task info
  }
  return (uint64_t)vm_info.ledger_phys_footprint_peak;
#endif
#elif PLATFORM_TYPE == PLATFORM_TYPE_UNIX
  return 0; // not implemented, but pass zero as temporary test of code
#elif PLATFORM_TYPE == PLATFORM_TYPE_WINDOWS
  return 0; // not implemented, but pass zero as temporary test of code
#else
#error "unsupported platform type (not implemented for this platform)"
#endif
}
