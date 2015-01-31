/**
   pthread.c

   Copyright (C) 1999, RTFM, Inc.
   All Rights Reserved.

   ekr@rtfm.com  Tue Feb 23 15:08:03 1999
 */


static char *RCSSTRING="$Id: pthread.c,v 1.1.1.1 2000/10/09 00:45:39 ekr Exp $";

#include <r_common.h>
#include <r_thread.h>
#include <pthread.h>

static int thread_count=0;

typedef struct {
     void (*func) PROTO_LIST((void *));
     void *arg;
} helper;


static void *r_thread_real_create PROTO_LIST((void *arg));

static void *r_thread_real_create(arg)
  void *arg;
  {
    helper *h;

    h=(helper *)arg;

    thread_count++;

    h->func(h->arg);

    thread_count--;
    free(h);
    return(0);
  }
                     
int r_thread_fork(func,arg,id)
  void (*func) PROTO_LIST((void *));
  void *arg;
  r_thread *id;
  {
    pthread_t thread;
    helper *h;
    int r,_status;

    h=(helper *)malloc(sizeof(helper));
    
    h->func=func;
    h->arg=arg;
    
    if(r=pthread_create(&thread,0,r_thread_real_create,(void *)h))
      ABORT(R_INTERNAL);

    _status=0;
  abort:
    return(_status);
  }

int r_thread_yield()
  {
    pthread_yield();
  }

int r_thread_exit()
  {
    thread_count--;
    pthread_exit(0);
    return(0);
  }

int r_thread_wait_last()
  {
    do {
      pthread_yield();
      usleep(10000);
      DBG((0,"%d threads left",thread_count));
    } while (thread_count);

    return(0);
  }

int r_rwlock_create(lockp)
  r_rwlock **lockp;
  {
    pthread_rwlock_t *lock;
    int r;

    if(!(lock=(pthread_rwlock_t *)malloc(sizeof(pthread_rwlock_t))))
      ERETURN(R_NO_MEMORY);
    
    if(r=pthread_rwlock_init(lock,0))
      ERETURN(R_INTERNAL);

    *lockp=(void *)lock;
    return(0);
  }

int r_rwlock_destroy(lock)
  r_rwlock **lock;
  {
    pthread_rwlock_t *plock;

    if(!lock || !*lock)
      return(0);

    plock=(pthread_rwlock_t *)(*lock);
    
    pthread_rwlock_destroy(plock);

    return(0);
  }

int r_rwlock_lock(lock,action)
  r_rwlock *lock;
  int action;
  {
    pthread_rwlock_t *plock;
    int r,_status;
    
    plock=(pthread_rwlock_t *)lock;

    switch(action){
      case R_RWLOCK_UNLOCK:
	if(r=pthread_rwlock_unlock(plock))
	  ABORT(R_INTERNAL);
	break;
      case R_RWLOCK_RLOCK:
	if(r=pthread_rwlock_rdlock(plock))
	  ABORT(R_INTERNAL);
	break;
      case R_RWLOCK_WLOCK:
	if(r=pthread_rwlock_wrlock(plock))
	  ABORT(R_INTERNAL);
	break;
      default:
	ABORT(R_BAD_ARGS);
    }

    _status=0;
  abort:
    return(_status);
  }

	
    
