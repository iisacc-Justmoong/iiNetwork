#include <algorithm>
#include <chrono>
#include <limits>
#include <windows.h>

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#include <iiNetwork/ByteStream.h>
#include <iiNetwork/Transport.h>
#include <iiNetwork/Local.h>
#include <iiNetwork/Tls.h>

#if !defined(min) || !defined(max)
#error "iiNetwork public headers must preserve the consuming application's macros"
#endif
