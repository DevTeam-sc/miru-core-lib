#ifndef __MIRU_INJECT_CONTEXT_H__
#define __MIRU_INJECT_CONTEXT_H__

#ifdef NOLIBC
typedef void * pthread_t;
typedef struct _pthread_attr_t pthread_attr_t;
struct msghdr;
struct sockaddr;
typedef unsigned int socklen_t;
#else
# include <dlfcn.h>
# include <pthread.h>
# include <stdint.h>
# include <sys/mman.h>
# include <sys/socket.h>
#endif

typedef size_t MiruBootstrapStatus;
typedef struct _MiruBootstrapContext MiruBootstrapContext;
typedef struct _MiruLoaderContext MiruLoaderContext;
typedef struct _MiruLibcApi MiruLibcApi;
typedef uint8_t MiruMessageType;
typedef struct _MiruHelloMessage MiruHelloMessage;
typedef struct _MiruByeMessage MiruByeMessage;
typedef int MiruRtldFlavor;

enum _MiruBootstrapStatus
{
  MIRU_BOOTSTRAP_ALLOCATION_SUCCESS,
  MIRU_BOOTSTRAP_ALLOCATION_ERROR,

  MIRU_BOOTSTRAP_SUCCESS,
  MIRU_BOOTSTRAP_AUXV_NOT_FOUND,
  MIRU_BOOTSTRAP_TOO_EARLY,
  MIRU_BOOTSTRAP_LIBC_LOAD_ERROR,
  MIRU_BOOTSTRAP_LIBC_UNSUPPORTED,
};

struct _MiruBootstrapContext
{
  void * allocation_base;
  size_t allocation_size;

  size_t page_size;
  const char * fallback_ld;
  const char * fallback_libc;
  MiruRtldFlavor rtld_flavor;
  void * rtld_base;
  void * r_brk;
  int enable_ctrlfds;
  int ctrlfds[2];
  MiruLibcApi * libc;
};

struct _MiruLoaderContext
{
  int ctrlfds[2];
  const char * agent_entrypoint;
  const char * agent_data;
  const char * fallback_address;
  MiruLibcApi * libc;

  pthread_t worker;
  void * agent_handle;
  void (* agent_entrypoint_impl) (const char * data, int * unload_policy, void * injector_state);
};

struct _MiruLibcApi
{
  int (* printf) (const char * format, ...);
  int (* sprintf) (char * str, const char * format, ...);

  void * (* mmap) (void * addr, size_t length, int prot, int flags, int fd, off_t offset);
  int (* munmap) (void * addr, size_t length);
  int (* socket) (int domain, int type, int protocol);
  int (* socketpair) (int domain, int type, int protocol, int sv[2]);
  int (* connect) (int sockfd, const struct sockaddr * addr, socklen_t addrlen);
  ssize_t (* recvmsg) (int sockfd, struct msghdr * msg, int flags);
  ssize_t (* send) (int sockfd, const void * buf, size_t len, int flags);
  int (* fcntl) (int fd, int cmd, ...);
  int (* close) (int fd);

  int (* pthread_create) (pthread_t * thread, const pthread_attr_t * attr, void * (* start_routine) (void *), void * arg);
  int (* pthread_detach) (pthread_t thread);

  void * (* dlopen) (const char * filename, int flags, const void * caller_addr);
  int dlopen_flags;
  int (* dlclose) (void * handle);
  void * (* dlsym) (void * handle, const char * symbol, const void * caller_addr);
  char * (* dlerror) (void);
};

enum _MiruMessageType
{
  MIRU_MESSAGE_HELLO,
  MIRU_MESSAGE_READY,
  MIRU_MESSAGE_ACK,
  MIRU_MESSAGE_BYE,
  MIRU_MESSAGE_ERROR_DLOPEN,
  MIRU_MESSAGE_ERROR_DLSYM,
};

struct _MiruHelloMessage
{
  pid_t thread_id;
};

struct _MiruByeMessage
{
  int unload_policy;
};

enum _MiruRtldFlavor
{
  MIRU_RTLD_UNKNOWN,
  MIRU_RTLD_NONE,
  MIRU_RTLD_GLIBC,
  MIRU_RTLD_UCLIBC,
  MIRU_RTLD_MUSL,
  MIRU_RTLD_ANDROID,
};

#endif
