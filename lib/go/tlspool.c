/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.10
 *
 * This file is not intended to be easily readable and contains a number of
 * coding conventions designed to improve portability and efficiency. Do not make
 * changes to this file unless you know what you are doing--modify the SWIG
 * interface file instead.
 * ----------------------------------------------------------------------------- */

/* source: go-tlspool.i */

#define SWIGMODULE tlspool
/* -----------------------------------------------------------------------------
 *  This section contains generic SWIG labels for method/variable
 *  declarations/attributes, and other compiler dependent labels.
 * ----------------------------------------------------------------------------- */

/* template workaround for compilers that cannot correctly implement the C++ standard */
#ifndef SWIGTEMPLATEDISAMBIGUATOR
# if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x560)
#  define SWIGTEMPLATEDISAMBIGUATOR template
# elif defined(__HP_aCC)
/* Needed even with `aCC -AA' when `aCC -V' reports HP ANSI C++ B3910B A.03.55 */
/* If we find a maximum version that requires this, the test would be __HP_aCC <= 35500 for A.03.55 */
#  define SWIGTEMPLATEDISAMBIGUATOR template
# else
#  define SWIGTEMPLATEDISAMBIGUATOR
# endif
#endif

/* inline attribute */
#ifndef SWIGINLINE
# if defined(__cplusplus) || (defined(__GNUC__) && !defined(__STRICT_ANSI__))
#   define SWIGINLINE inline
# else
#   define SWIGINLINE
# endif
#endif

/* attribute recognised by some compilers to avoid 'unused' warnings */
#ifndef SWIGUNUSED
# if defined(__GNUC__)
#   if !(defined(__cplusplus)) || (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#     define SWIGUNUSED __attribute__ ((__unused__))
#   else
#     define SWIGUNUSED
#   endif
# elif defined(__ICC)
#   define SWIGUNUSED __attribute__ ((__unused__))
# else
#   define SWIGUNUSED
# endif
#endif

#ifndef SWIG_MSC_UNSUPPRESS_4505
# if defined(_MSC_VER)
#   pragma warning(disable : 4505) /* unreferenced local function has been removed */
# endif
#endif

#ifndef SWIGUNUSEDPARM
# ifdef __cplusplus
#   define SWIGUNUSEDPARM(p)
# else
#   define SWIGUNUSEDPARM(p) p SWIGUNUSED
# endif
#endif

/* internal SWIG method */
#ifndef SWIGINTERN
# define SWIGINTERN static SWIGUNUSED
#endif

/* internal inline SWIG method */
#ifndef SWIGINTERNINLINE
# define SWIGINTERNINLINE SWIGINTERN SWIGINLINE
#endif

/* exporting methods */
#if defined(__GNUC__)
#  if (__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#    ifndef GCC_HASCLASSVISIBILITY
#      define GCC_HASCLASSVISIBILITY
#    endif
#  endif
#endif

#ifndef SWIGEXPORT
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   if defined(STATIC_LINKED)
#     define SWIGEXPORT
#   else
#     define SWIGEXPORT __declspec(dllexport)
#   endif
# else
#   if defined(__GNUC__) && defined(GCC_HASCLASSVISIBILITY)
#     define SWIGEXPORT __attribute__ ((visibility("default")))
#   else
#     define SWIGEXPORT
#   endif
# endif
#endif

/* calling conventions for Windows */
#ifndef SWIGSTDCALL
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   define SWIGSTDCALL __stdcall
# else
#   define SWIGSTDCALL
# endif
#endif

/* Deal with Microsoft's attempt at deprecating C standard runtime functions */
#if !defined(SWIG_NO_CRT_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
# define _CRT_SECURE_NO_DEPRECATE
#endif

/* Deal with Microsoft's attempt at deprecating methods in the standard C++ library */
#if !defined(SWIG_NO_SCL_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_SCL_SECURE_NO_DEPRECATE)
# define _SCL_SECURE_NO_DEPRECATE
#endif

/* Deal with Apple's deprecated 'AssertMacros.h' from Carbon-framework */
#if defined(__APPLE__) && !defined(__ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES)
# define __ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES 0
#endif

/* Intel's compiler complains if a variable which was never initialised is
 * cast to void, which is a common idiom which we use to indicate that we
 * are aware a variable isn't used.  So we just silence that warning.
 * See: https://github.com/swig/swig/issues/192 for more discussion.
 */
#ifdef __INTEL_COMPILER
# pragma warning disable 592
#endif


#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>



typedef long long intgo;
typedef unsigned long long uintgo;


# if !defined(__clang__) && (defined(__i386__) || defined(__x86_64__))
#   define SWIGSTRUCTPACKED __attribute__((__packed__, __gcc_struct__))
# else
#   define SWIGSTRUCTPACKED __attribute__((__packed__))
# endif



typedef struct { char *p; intgo n; } _gostring_;
typedef struct { void* array; intgo len; intgo cap; } _goslice_;




#define swiggo_size_assert_eq(x, y, name) typedef char name[(x-y)*(x-y)*-2+1];
#define swiggo_size_assert(t, n) swiggo_size_assert_eq(sizeof(t), n, swiggo_sizeof_##t##_is_not_##n)

swiggo_size_assert(char, 1)
swiggo_size_assert(short, 2)
swiggo_size_assert(int, 4)
typedef long long swiggo_long_long;
swiggo_size_assert(swiggo_long_long, 8)
swiggo_size_assert(float, 4)
swiggo_size_assert(double, 8)

#ifdef __cplusplus
extern "C" {
#endif
extern void crosscall2(void (*fn)(void *, int), void *, int);
extern char* _cgo_topofstack(void) __attribute__ ((weak));
extern void _cgo_allocate(void *, int);
extern void _cgo_panic(void *, int);
#ifdef __cplusplus
}
#endif

static char *_swig_topofstack() {
  if (_cgo_topofstack) {
    return _cgo_topofstack();
  } else {
    return 0;
  }
}

static void _swig_gopanic(const char *p) {
  struct {
    const char *p;
  } SWIGSTRUCTPACKED a;
  a.p = p;
  crosscall2(_cgo_panic, &a, (int) sizeof a);
}




#define SWIG_contract_assert(expr, msg) \
  if (!(expr)) { _swig_gopanic(msg); } else


static _gostring_ Swig_AllocateString(const char *p, size_t l) {
  _gostring_ ret;
  ret.p = (char*)malloc(l);
  memcpy(ret.p, p, l);
  ret.n = l;
  return ret;
}


static void Swig_free(void* p) {
  free(p);
}

static void* Swig_malloc(int c) {
  return malloc(c);
}



#include <tlspool/starttls.h>
#include <tlspool/commands.h>




	typedef char identity_t [128];

	typedef uint8_t ctlkey_t [16];

	typedef char service_t [16];

	typedef int int;

	typedef struct {
		int tlserrno;
		char message [128];
	} error_data;

	typedef struct {
		char YYYYMMDD_producer [8+128];	// when & who?
		uint32_t facilities;		// PIOF_FACILITY_xxx
	} ping_data;

	typedef struct {
		uint32_t flags;
		uint32_t local;
		uint8_t ipproto;
		uint16_t streamid;
		identity_t localid;
		identity_t remoteid;
		ctlkey_t ctlkey;
		service_t service;
		uint32_t timeout;
	} starttls_data;

	typedef struct {
		uint32_t flags;
		ctlkey_t ctlkey;
		identity_t name;
	} control_data;

	typedef struct {
		int16_t in1_len, in2_len, prng_len;
		uint8_t buffer [350];
	} prng_data;

	typedef union {
		int unix_socket;
	} socket_data;


#ifdef __cplusplus
extern "C" {
#endif

void _wrap_Swig_free_tlspool_03ad2d7a43d805c7(void *_swig_go_0) {
  void *arg1 = (void *) 0 ;
  
  arg1 = *(void **)&_swig_go_0; 
  
  Swig_free(arg1);
  
}


void *_wrap_Swig_malloc_tlspool_03ad2d7a43d805c7(intgo _swig_go_0) {
  int arg1 ;
  void *result = 0 ;
  void *_swig_go_result;
  
  arg1 = (int)_swig_go_0; 
  
  result = (void *)Swig_malloc(arg1);
  *(void **)&_swig_go_result = (void *)result; 
  return _swig_go_result;
}


void _wrap_error_data_tlserrno_set_tlspool_03ad2d7a43d805c7(error_data *_swig_go_0, intgo _swig_go_1) {
  error_data *arg1 = (error_data *) 0 ;
  int arg2 ;
  
  arg1 = *(error_data **)&_swig_go_0; 
  arg2 = (int)_swig_go_1; 
  
  if (arg1) (arg1)->tlserrno = arg2;
  
}


intgo _wrap_error_data_tlserrno_get_tlspool_03ad2d7a43d805c7(error_data *_swig_go_0) {
  error_data *arg1 = (error_data *) 0 ;
  int result;
  intgo _swig_go_result;
  
  arg1 = *(error_data **)&_swig_go_0; 
  
  result = (int) ((arg1)->tlserrno);
  _swig_go_result = result; 
  return _swig_go_result;
}


void _wrap_error_data_message_set_tlspool_03ad2d7a43d805c7(error_data *_swig_go_0, _gostring_ _swig_go_1) {
  error_data *arg1 = (error_data *) 0 ;
  char *arg2 ;
  
  arg1 = *(error_data **)&_swig_go_0; 
  
  arg2 = (char *)malloc(_swig_go_1.n + 1);
  memcpy(arg2, _swig_go_1.p, _swig_go_1.n);
  arg2[_swig_go_1.n] = '\0';
  
  
  {
    if(arg2) {
      strncpy((char*)arg1->message, (const char *)arg2, 128-1);
      arg1->message[128-1] = 0;
    } else {
      arg1->message[0] = 0;
    }
  }
  
  free(arg2); 
}


_gostring_ _wrap_error_data_message_get_tlspool_03ad2d7a43d805c7(error_data *_swig_go_0) {
  error_data *arg1 = (error_data *) 0 ;
  char *result = 0 ;
  _gostring_ _swig_go_result;
  
  arg1 = *(error_data **)&_swig_go_0; 
  
  result = (char *)(char *) ((arg1)->message);
  _swig_go_result = Swig_AllocateString((char*)result, result ? strlen((char*)result) : 0); 
  return _swig_go_result;
}


error_data *_wrap_new_error_data_tlspool_03ad2d7a43d805c7() {
  error_data *result = 0 ;
  error_data *_swig_go_result;
  
  
  result = (error_data *)calloc(1, sizeof(error_data));
  *(error_data **)&_swig_go_result = (error_data *)result; 
  return _swig_go_result;
}


void _wrap_delete_error_data_tlspool_03ad2d7a43d805c7(error_data *_swig_go_0) {
  error_data *arg1 = (error_data *) 0 ;
  
  arg1 = *(error_data **)&_swig_go_0; 
  
  free((char *) arg1);
  
}


void _wrap_ping_data_YYYYMMDD_producer_set_tlspool_03ad2d7a43d805c7(ping_data *_swig_go_0, _gostring_ _swig_go_1) {
  ping_data *arg1 = (ping_data *) 0 ;
  char *arg2 ;
  
  arg1 = *(ping_data **)&_swig_go_0; 
  
  arg2 = (char *)malloc(_swig_go_1.n + 1);
  memcpy(arg2, _swig_go_1.p, _swig_go_1.n);
  arg2[_swig_go_1.n] = '\0';
  
  
  {
    if(arg2) {
      strncpy((char*)arg1->YYYYMMDD_producer, (const char *)arg2, 8+128-1);
      arg1->YYYYMMDD_producer[8+128-1] = 0;
    } else {
      arg1->YYYYMMDD_producer[0] = 0;
    }
  }
  
  free(arg2); 
}


_gostring_ _wrap_ping_data_YYYYMMDD_producer_get_tlspool_03ad2d7a43d805c7(ping_data *_swig_go_0) {
  ping_data *arg1 = (ping_data *) 0 ;
  char *result = 0 ;
  _gostring_ _swig_go_result;
  
  arg1 = *(ping_data **)&_swig_go_0; 
  
  result = (char *)(char *) ((arg1)->YYYYMMDD_producer);
  _swig_go_result = Swig_AllocateString((char*)result, result ? strlen((char*)result) : 0); 
  return _swig_go_result;
}


void _wrap_ping_data_facilities_set_tlspool_03ad2d7a43d805c7(ping_data *_swig_go_0, intgo _swig_go_1) {
  ping_data *arg1 = (ping_data *) 0 ;
  uint32_t arg2 ;
  
  arg1 = *(ping_data **)&_swig_go_0; 
  arg2 = (uint32_t)_swig_go_1; 
  
  if (arg1) (arg1)->facilities = arg2;
  
}


intgo _wrap_ping_data_facilities_get_tlspool_03ad2d7a43d805c7(ping_data *_swig_go_0) {
  ping_data *arg1 = (ping_data *) 0 ;
  uint32_t result;
  intgo _swig_go_result;
  
  arg1 = *(ping_data **)&_swig_go_0; 
  
  result =  ((arg1)->facilities);
  _swig_go_result = result; 
  return _swig_go_result;
}


ping_data *_wrap_new_ping_data_tlspool_03ad2d7a43d805c7() {
  ping_data *result = 0 ;
  ping_data *_swig_go_result;
  
  
  result = (ping_data *)calloc(1, sizeof(ping_data));
  *(ping_data **)&_swig_go_result = (ping_data *)result; 
  return _swig_go_result;
}


void _wrap_delete_ping_data_tlspool_03ad2d7a43d805c7(ping_data *_swig_go_0) {
  ping_data *arg1 = (ping_data *) 0 ;
  
  arg1 = *(ping_data **)&_swig_go_0; 
  
  free((char *) arg1);
  
}


void _wrap_starttls_data_flags_set_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0, intgo _swig_go_1) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint32_t arg2 ;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  arg2 = (uint32_t)_swig_go_1; 
  
  if (arg1) (arg1)->flags = arg2;
  
}


intgo _wrap_starttls_data_flags_get_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint32_t result;
  intgo _swig_go_result;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  result =  ((arg1)->flags);
  _swig_go_result = result; 
  return _swig_go_result;
}


void _wrap_starttls_data_local_set_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0, intgo _swig_go_1) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint32_t arg2 ;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  arg2 = (uint32_t)_swig_go_1; 
  
  if (arg1) (arg1)->local = arg2;
  
}


intgo _wrap_starttls_data_local_get_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint32_t result;
  intgo _swig_go_result;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  result =  ((arg1)->local);
  _swig_go_result = result; 
  return _swig_go_result;
}


void _wrap_starttls_data_ipproto_set_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0, char _swig_go_1) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint8_t arg2 ;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  arg2 = (uint8_t)_swig_go_1; 
  
  if (arg1) (arg1)->ipproto = arg2;
  
}


char _wrap_starttls_data_ipproto_get_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint8_t result;
  char _swig_go_result;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  result =  ((arg1)->ipproto);
  _swig_go_result = result; 
  return _swig_go_result;
}


void _wrap_starttls_data_streamid_set_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0, short _swig_go_1) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint16_t arg2 ;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  arg2 = (uint16_t)_swig_go_1; 
  
  if (arg1) (arg1)->streamid = arg2;
  
}


short _wrap_starttls_data_streamid_get_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint16_t result;
  short _swig_go_result;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  result =  ((arg1)->streamid);
  _swig_go_result = result; 
  return _swig_go_result;
}


void _wrap_starttls_data_localid_set_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0, _gostring_ _swig_go_1) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  char *arg2 ;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  arg2 = (char *)malloc(_swig_go_1.n + 1);
  memcpy(arg2, _swig_go_1.p, _swig_go_1.n);
  arg2[_swig_go_1.n] = '\0';
  
  
  {
    if(arg2) {
      strncpy((char*)arg1->localid, (const char *)arg2, 128-1);
      arg1->localid[128-1] = 0;
    } else {
      arg1->localid[0] = 0;
    }
  }
  
  free(arg2); 
}


_gostring_ _wrap_starttls_data_localid_get_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  char *result = 0 ;
  _gostring_ _swig_go_result;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  result = (char *) ((arg1)->localid);
  _swig_go_result = Swig_AllocateString((char*)result, result ? strlen((char*)result) : 0); 
  return _swig_go_result;
}


void _wrap_starttls_data_remoteid_set_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0, _gostring_ _swig_go_1) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  char *arg2 ;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  arg2 = (char *)malloc(_swig_go_1.n + 1);
  memcpy(arg2, _swig_go_1.p, _swig_go_1.n);
  arg2[_swig_go_1.n] = '\0';
  
  
  {
    if(arg2) {
      strncpy((char*)arg1->remoteid, (const char *)arg2, 128-1);
      arg1->remoteid[128-1] = 0;
    } else {
      arg1->remoteid[0] = 0;
    }
  }
  
  free(arg2); 
}


_gostring_ _wrap_starttls_data_remoteid_get_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  char *result = 0 ;
  _gostring_ _swig_go_result;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  result = (char *) ((arg1)->remoteid);
  _swig_go_result = Swig_AllocateString((char*)result, result ? strlen((char*)result) : 0); 
  return _swig_go_result;
}


void _wrap_starttls_data_ctlkey_set_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0, char *_swig_go_1) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint8_t *arg2 ;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  arg2 = *(uint8_t **)&_swig_go_1; 
  
  {
    size_t ii;
    uint8_t *b = (uint8_t *) arg1->ctlkey;
    for (ii = 0; ii < (size_t)16; ii++) b[ii] = *((uint8_t *) arg2 + ii);
  }
  
}


char *_wrap_starttls_data_ctlkey_get_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint8_t *result = 0 ;
  char *_swig_go_result;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  result = (uint8_t *) ((arg1)->ctlkey);
  *(uint8_t **)&_swig_go_result = result; 
  return _swig_go_result;
}


void _wrap_starttls_data_service_set_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0, _gostring_ _swig_go_1) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  char *arg2 ;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  arg2 = (char *)malloc(_swig_go_1.n + 1);
  memcpy(arg2, _swig_go_1.p, _swig_go_1.n);
  arg2[_swig_go_1.n] = '\0';
  
  
  {
    if(arg2) {
      strncpy((char*)arg1->service, (const char *)arg2, 16-1);
      arg1->service[16-1] = 0;
    } else {
      arg1->service[0] = 0;
    }
  }
  
  free(arg2); 
}


_gostring_ _wrap_starttls_data_service_get_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  char *result = 0 ;
  _gostring_ _swig_go_result;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  result = (char *) ((arg1)->service);
  _swig_go_result = Swig_AllocateString((char*)result, result ? strlen((char*)result) : 0); 
  return _swig_go_result;
}


void _wrap_starttls_data_timeout_set_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0, intgo _swig_go_1) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint32_t arg2 ;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  arg2 = (uint32_t)_swig_go_1; 
  
  if (arg1) (arg1)->timeout = arg2;
  
}


intgo _wrap_starttls_data_timeout_get_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  uint32_t result;
  intgo _swig_go_result;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  result =  ((arg1)->timeout);
  _swig_go_result = result; 
  return _swig_go_result;
}


starttls_data *_wrap_new_starttls_data_tlspool_03ad2d7a43d805c7() {
  starttls_data *result = 0 ;
  starttls_data *_swig_go_result;
  
  
  result = (starttls_data *)calloc(1, sizeof(starttls_data));
  *(starttls_data **)&_swig_go_result = (starttls_data *)result; 
  return _swig_go_result;
}


void _wrap_delete_starttls_data_tlspool_03ad2d7a43d805c7(starttls_data *_swig_go_0) {
  starttls_data *arg1 = (starttls_data *) 0 ;
  
  arg1 = *(starttls_data **)&_swig_go_0; 
  
  free((char *) arg1);
  
}


void _wrap_control_data_flags_set_tlspool_03ad2d7a43d805c7(control_data *_swig_go_0, intgo _swig_go_1) {
  control_data *arg1 = (control_data *) 0 ;
  uint32_t arg2 ;
  
  arg1 = *(control_data **)&_swig_go_0; 
  arg2 = (uint32_t)_swig_go_1; 
  
  if (arg1) (arg1)->flags = arg2;
  
}


intgo _wrap_control_data_flags_get_tlspool_03ad2d7a43d805c7(control_data *_swig_go_0) {
  control_data *arg1 = (control_data *) 0 ;
  uint32_t result;
  intgo _swig_go_result;
  
  arg1 = *(control_data **)&_swig_go_0; 
  
  result =  ((arg1)->flags);
  _swig_go_result = result; 
  return _swig_go_result;
}


void _wrap_control_data_ctlkey_set_tlspool_03ad2d7a43d805c7(control_data *_swig_go_0, char *_swig_go_1) {
  control_data *arg1 = (control_data *) 0 ;
  uint8_t *arg2 ;
  
  arg1 = *(control_data **)&_swig_go_0; 
  arg2 = *(uint8_t **)&_swig_go_1; 
  
  {
    size_t ii;
    uint8_t *b = (uint8_t *) arg1->ctlkey;
    for (ii = 0; ii < (size_t)16; ii++) b[ii] = *((uint8_t *) arg2 + ii);
  }
  
}


char *_wrap_control_data_ctlkey_get_tlspool_03ad2d7a43d805c7(control_data *_swig_go_0) {
  control_data *arg1 = (control_data *) 0 ;
  uint8_t *result = 0 ;
  char *_swig_go_result;
  
  arg1 = *(control_data **)&_swig_go_0; 
  
  result = (uint8_t *) ((arg1)->ctlkey);
  *(uint8_t **)&_swig_go_result = result; 
  return _swig_go_result;
}


void _wrap_control_data_name_set_tlspool_03ad2d7a43d805c7(control_data *_swig_go_0, _gostring_ _swig_go_1) {
  control_data *arg1 = (control_data *) 0 ;
  char *arg2 ;
  
  arg1 = *(control_data **)&_swig_go_0; 
  
  arg2 = (char *)malloc(_swig_go_1.n + 1);
  memcpy(arg2, _swig_go_1.p, _swig_go_1.n);
  arg2[_swig_go_1.n] = '\0';
  
  
  {
    if(arg2) {
      strncpy((char*)arg1->name, (const char *)arg2, 128-1);
      arg1->name[128-1] = 0;
    } else {
      arg1->name[0] = 0;
    }
  }
  
  free(arg2); 
}


_gostring_ _wrap_control_data_name_get_tlspool_03ad2d7a43d805c7(control_data *_swig_go_0) {
  control_data *arg1 = (control_data *) 0 ;
  char *result = 0 ;
  _gostring_ _swig_go_result;
  
  arg1 = *(control_data **)&_swig_go_0; 
  
  result = (char *) ((arg1)->name);
  _swig_go_result = Swig_AllocateString((char*)result, result ? strlen((char*)result) : 0); 
  return _swig_go_result;
}


control_data *_wrap_new_control_data_tlspool_03ad2d7a43d805c7() {
  control_data *result = 0 ;
  control_data *_swig_go_result;
  
  
  result = (control_data *)calloc(1, sizeof(control_data));
  *(control_data **)&_swig_go_result = (control_data *)result; 
  return _swig_go_result;
}


void _wrap_delete_control_data_tlspool_03ad2d7a43d805c7(control_data *_swig_go_0) {
  control_data *arg1 = (control_data *) 0 ;
  
  arg1 = *(control_data **)&_swig_go_0; 
  
  free((char *) arg1);
  
}


void _wrap_prng_data_in1_len_set_tlspool_03ad2d7a43d805c7(prng_data *_swig_go_0, short _swig_go_1) {
  prng_data *arg1 = (prng_data *) 0 ;
  int16_t arg2 ;
  
  arg1 = *(prng_data **)&_swig_go_0; 
  arg2 = (int16_t)_swig_go_1; 
  
  if (arg1) (arg1)->in1_len = arg2;
  
}


short _wrap_prng_data_in1_len_get_tlspool_03ad2d7a43d805c7(prng_data *_swig_go_0) {
  prng_data *arg1 = (prng_data *) 0 ;
  int16_t result;
  short _swig_go_result;
  
  arg1 = *(prng_data **)&_swig_go_0; 
  
  result =  ((arg1)->in1_len);
  _swig_go_result = result; 
  return _swig_go_result;
}


void _wrap_prng_data_in2_len_set_tlspool_03ad2d7a43d805c7(prng_data *_swig_go_0, short _swig_go_1) {
  prng_data *arg1 = (prng_data *) 0 ;
  int16_t arg2 ;
  
  arg1 = *(prng_data **)&_swig_go_0; 
  arg2 = (int16_t)_swig_go_1; 
  
  if (arg1) (arg1)->in2_len = arg2;
  
}


short _wrap_prng_data_in2_len_get_tlspool_03ad2d7a43d805c7(prng_data *_swig_go_0) {
  prng_data *arg1 = (prng_data *) 0 ;
  int16_t result;
  short _swig_go_result;
  
  arg1 = *(prng_data **)&_swig_go_0; 
  
  result =  ((arg1)->in2_len);
  _swig_go_result = result; 
  return _swig_go_result;
}


void _wrap_prng_data_prng_len_set_tlspool_03ad2d7a43d805c7(prng_data *_swig_go_0, short _swig_go_1) {
  prng_data *arg1 = (prng_data *) 0 ;
  int16_t arg2 ;
  
  arg1 = *(prng_data **)&_swig_go_0; 
  arg2 = (int16_t)_swig_go_1; 
  
  if (arg1) (arg1)->prng_len = arg2;
  
}


short _wrap_prng_data_prng_len_get_tlspool_03ad2d7a43d805c7(prng_data *_swig_go_0) {
  prng_data *arg1 = (prng_data *) 0 ;
  int16_t result;
  short _swig_go_result;
  
  arg1 = *(prng_data **)&_swig_go_0; 
  
  result =  ((arg1)->prng_len);
  _swig_go_result = result; 
  return _swig_go_result;
}


void _wrap_prng_data_buffer_set_tlspool_03ad2d7a43d805c7(prng_data *_swig_go_0, char *_swig_go_1) {
  prng_data *arg1 = (prng_data *) 0 ;
  uint8_t *arg2 ;
  
  arg1 = *(prng_data **)&_swig_go_0; 
  arg2 = *(uint8_t **)&_swig_go_1; 
  
  {
    size_t ii;
    uint8_t *b = (uint8_t *) arg1->buffer;
    for (ii = 0; ii < (size_t)350; ii++) b[ii] = *((uint8_t *) arg2 + ii);
  }
  
}


char *_wrap_prng_data_buffer_get_tlspool_03ad2d7a43d805c7(prng_data *_swig_go_0) {
  prng_data *arg1 = (prng_data *) 0 ;
  uint8_t *result = 0 ;
  char *_swig_go_result;
  
  arg1 = *(prng_data **)&_swig_go_0; 
  
  result = (uint8_t *)(uint8_t *) ((arg1)->buffer);
  *(uint8_t **)&_swig_go_result = result; 
  return _swig_go_result;
}


prng_data *_wrap_new_prng_data_tlspool_03ad2d7a43d805c7() {
  prng_data *result = 0 ;
  prng_data *_swig_go_result;
  
  
  result = (prng_data *)calloc(1, sizeof(prng_data));
  *(prng_data **)&_swig_go_result = (prng_data *)result; 
  return _swig_go_result;
}


void _wrap_delete_prng_data_tlspool_03ad2d7a43d805c7(prng_data *_swig_go_0) {
  prng_data *arg1 = (prng_data *) 0 ;
  
  arg1 = *(prng_data **)&_swig_go_0; 
  
  free((char *) arg1);
  
}


void _wrap_socket_data_unix_socket_set_tlspool_03ad2d7a43d805c7(socket_data *_swig_go_0, intgo _swig_go_1) {
  socket_data *arg1 = (socket_data *) 0 ;
  int arg2 ;
  
  arg1 = *(socket_data **)&_swig_go_0; 
  arg2 = (int)_swig_go_1; 
  
  if (arg1) (arg1)->unix_socket = arg2;
  
}


intgo _wrap_socket_data_unix_socket_get_tlspool_03ad2d7a43d805c7(socket_data *_swig_go_0) {
  socket_data *arg1 = (socket_data *) 0 ;
  int result;
  intgo _swig_go_result;
  
  arg1 = *(socket_data **)&_swig_go_0; 
  
  result = (int) ((arg1)->unix_socket);
  _swig_go_result = result; 
  return _swig_go_result;
}


socket_data *_wrap_new_socket_data_tlspool_03ad2d7a43d805c7() {
  socket_data *result = 0 ;
  socket_data *_swig_go_result;
  
  
  result = (socket_data *)calloc(1, sizeof(socket_data));
  *(socket_data **)&_swig_go_result = (socket_data *)result; 
  return _swig_go_result;
}


void _wrap_delete_socket_data_tlspool_03ad2d7a43d805c7(socket_data *_swig_go_0) {
  socket_data *arg1 = (socket_data *) 0 ;
  
  arg1 = *(socket_data **)&_swig_go_0; 
  
  free((char *) arg1);
  
}


intgo _wrap_Internal_pid_tlspool_03ad2d7a43d805c7(_gostring_ _swig_go_0) {
  char *arg1 = (char *) 0 ;
  int result;
  intgo _swig_go_result;
  
  
  arg1 = (char *)malloc(_swig_go_0.n + 1);
  memcpy(arg1, _swig_go_0.p, _swig_go_0.n);
  arg1[_swig_go_0.n] = '\0';
  
  
  result = (int)tlspool_pid(arg1);
  _swig_go_result = result; 
  free(arg1); 
  return _swig_go_result;
}


intgo _wrap_Internal_open_poolhandle_tlspool_03ad2d7a43d805c7(_gostring_ _swig_go_0) {
  char *arg1 = (char *) 0 ;
  int result;
  intgo _swig_go_result;
  
  
  arg1 = (char *)malloc(_swig_go_0.n + 1);
  memcpy(arg1, _swig_go_0.p, _swig_go_0.n);
  arg1[_swig_go_0.n] = '\0';
  
  
  result = (int)tlspool_open_poolhandle(arg1);
  _swig_go_result = result; 
  free(arg1); 
  return _swig_go_result;
}


intgo _wrap_Internal_ping_tlspool_03ad2d7a43d805c7(ping_data *_swig_go_0) {
  ping_data *arg1 = (ping_data *) 0 ;
  int result;
  intgo _swig_go_result;
  
  arg1 = *(ping_data **)&_swig_go_0; 
  
  result = (int)tlspool_ping(arg1);
  _swig_go_result = result; 
  return _swig_go_result;
}


intgo _wrap_Internal_starttls_tlspool_03ad2d7a43d805c7(intgo _swig_go_0, starttls_data *_swig_go_1, void *_swig_go_2, void *_swig_go_3) {
  int arg1 ;
  starttls_data *arg2 = (starttls_data *) 0 ;
  void *arg3 = (void *) 0 ;
  void *arg4 = (void *) 0 ;
  int result;
  intgo _swig_go_result;
  
  arg1 = (int)_swig_go_0; 
  arg2 = *(starttls_data **)&_swig_go_1; 
  arg3 = *(void **)&_swig_go_2; 
  arg4 = *(void **)&_swig_go_3; 
  
  result = (int)tlspool_starttls(arg1,arg2,arg3,arg4);
  _swig_go_result = result; 
  return _swig_go_result;
}


intgo _wrap_Internal_control_detach_tlspool_03ad2d7a43d805c7(char *_swig_go_0) {
  uint8_t *arg1 ;
  int result;
  intgo _swig_go_result;
  
  arg1 = *(uint8_t **)&_swig_go_0; 
  
  result = (int)tlspool_control_detach(arg1);
  _swig_go_result = result; 
  return _swig_go_result;
}


intgo _wrap_Internal_control_reattach_tlspool_03ad2d7a43d805c7(char *_swig_go_0) {
  uint8_t *arg1 ;
  int result;
  intgo _swig_go_result;
  
  arg1 = *(uint8_t **)&_swig_go_0; 
  
  result = (int)tlspool_control_reattach(arg1);
  _swig_go_result = result; 
  return _swig_go_result;
}


intgo _wrap_Internal_prng_tlspool_03ad2d7a43d805c7(_gostring_ _swig_go_0, _gostring_ _swig_go_1, short _swig_go_2, char *_swig_go_3, char *_swig_go_4) {
  char *arg1 = (char *) 0 ;
  char *arg2 = (char *) 0 ;
  uint16_t arg3 ;
  uint8_t *arg4 = (uint8_t *) 0 ;
  uint8_t *arg5 ;
  int result;
  intgo _swig_go_result;
  
  
  arg1 = (char *)malloc(_swig_go_0.n + 1);
  memcpy(arg1, _swig_go_0.p, _swig_go_0.n);
  arg1[_swig_go_0.n] = '\0';
  
  
  arg2 = (char *)malloc(_swig_go_1.n + 1);
  memcpy(arg2, _swig_go_1.p, _swig_go_1.n);
  arg2[_swig_go_1.n] = '\0';
  
  arg3 = (uint16_t)_swig_go_2; 
  arg4 = *(uint8_t **)&_swig_go_3; 
  arg5 = *(uint8_t **)&_swig_go_4; 
  
  result = (int)tlspool_prng(arg1,arg2,arg3,arg4,arg5);
  _swig_go_result = result; 
  free(arg1); 
  free(arg2); 
  return _swig_go_result;
}


_gostring_ _wrap_tlspool_configvar_tlspool_03ad2d7a43d805c7(_gostring_ _swig_go_0, _gostring_ _swig_go_1) {
  char *arg1 = (char *) 0 ;
  char *arg2 = (char *) 0 ;
  char *result = 0 ;
  _gostring_ _swig_go_result;
  
  
  arg1 = (char *)malloc(_swig_go_0.n + 1);
  memcpy(arg1, _swig_go_0.p, _swig_go_0.n);
  arg1[_swig_go_0.n] = '\0';
  
  
  arg2 = (char *)malloc(_swig_go_1.n + 1);
  memcpy(arg2, _swig_go_1.p, _swig_go_1.n);
  arg2[_swig_go_1.n] = '\0';
  
  
  result = (char *)tlspool_configvar(arg1,arg2);
  _swig_go_result = Swig_AllocateString((char*)result, result ? strlen((char*)result) : 0); 
  free(arg1); 
  free(arg2); 
  return _swig_go_result;
}


intgo _wrap_PIOC_LOCAL_tlspool_03ad2d7a43d805c7() {
  int result;
  intgo _swig_go_result;
  
  
  result = -0x80000000;
  
  _swig_go_result = result; 
  return _swig_go_result;
}


#ifdef __cplusplus
}
#endif

