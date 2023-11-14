#ifndef CONFIG_PLATFORM_H
#define CONFIG_PLATFORM_H
/*
  Purpose

  This intended usage of this file is to enable platform (OS and hardware) dependent code in a simple way.
  That is, while the core parts of the implementation is unoptimized and platform independent, some things like,
  for example, timing measurements may sometimes require OS dependent functionality to be used.

  Our intent is to keep thing very simple, providing an easy way to diverge implementations for
  * MAC,
  * Unix (Linux type systems other than MAC), and
  * Windows.
  Hopefully this will be enough for our purposes, we will see if the need develops further.

  We provide some defines below, so please specify your target platform.
  We prefer to put the defines in  this file rather than to promote compile-time defines since we can
  provide a bit of explanation here if necessary.
*/
#define PLATFORM_TYPE_MAC     0
#define PLATFORM_TYPE_UNIX    1
#define PLATFORM_TYPE_WINDOWS 2

// set PLATFORM_TYPE to precisely one of the above
#define PLATFORM_TYPE PLATFORM_TYPE_MAC

#ifndef PLATFORM_TYPE
#error "PLATFORM_TYPE undefined, see config_platform.h"
#elif ((PLATFORM_TYPE != PLATFORM_TYPE_MAC) && \
     (PLATFORM_TYPE != PLATFORM_TYPE_UNIX) && \
     (PLATFORM_TYPE != PLATFORM_TYPE_WINDOWS))
#error "PLATFORM_TYPE unsupported, see config_platform.h"
#endif

#endif
