#ifndef PLATFORM_MEASUREMENT_UTILS_H
#define PLATFORM_MEASUREMENT_UTILS_H
#include "config_platform.h"

#if PLATFORM_TYPE == PLATFORM_TYPE_MAC
#include <inttypes.h>
typedef uint64_t platform_time_type;
#elif PLATFORM_TYPE == PLATFORM_TYPE_UNIX
#include <inttypes.h>
typedef double platform_time_type;
#elif PLATFORM_TYPE == PLATFORM_TYPE_WINDOWS
#include <inttypes.h>
#include <time.h>
typedef clock_t platform_time_type;
#else
#error "unsupported platform type"
#endif

platform_time_type platform_utils_get_wall_time(void);
double platform_utils_get_wall_time_diff(platform_time_type start_time, platform_time_type end_time);

uint64_t platform_utils_get_max_memory_usage(void);

#endif
