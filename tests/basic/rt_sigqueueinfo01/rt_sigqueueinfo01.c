// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2019 SUSE LLC
 * Author: Christian Amann <camann@suse.com>
 */

/*
 * This tests the rt_sigqueueinfo() syscall.
 *
 * It does so by creating a thread which registers the corresponding
 * signal handler. After that the main thread sends a signal and data
 * to the handler thread. If the correct signal and data is received,
 * the test is successful.
 */

#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "pthread.h"
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>

typedef volatile uint32_t futex_t;

#define SIGNAL	SIGUSR1
#define DATA	777
#define DEFAULT_MSEC_TIMEOUT 100000
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
futex_t *tst_futexes1;

static struct sigaction *sig_action;
static int sig_rec;
static siginfo_t *uinfo;
static pid_t tid;


void futex_wait(unsigned int id)
{
	int ret;
	printf("errno: %i, %s\n",errno, strerror(errno));
	do {
		ret = syscall(SYS_futex, &tst_futexes1[id], FUTEX_WAIT,
			      tst_futexes1[id], NULL);
		printf("ret: %i, errno: %i, %s\n",ret, errno, strerror(errno));
	} while (ret == -1 && errno == EINTR);
	if (ret) {
		printf("tst_checkpoint_wait(%i) failed\n", id);
		exit(-1);
	}
}

void futex_wake(unsigned int id)
{
	unsigned int msecs = 0, waked = 0;
	int ret;

	for (;;) {
		waked += syscall(SYS_futex, &tst_futexes1[id], FUTEX_WAKE,
				 INT_MAX, NULL);

		if (waked == 1)
			break;

		usleep(1000);
		msecs++;

		if (msecs >= DEFAULT_MSEC_TIMEOUT) {
			errno = ETIMEDOUT;
			ret = -1;
		}
	}

	if (ret) {
		printf("tst_checkpoint_wake(%i)\n", id);
	}
}

static void received_signal(int sig, siginfo_t *info, void *ucontext)
{
	tid = syscall(SYS_gettid);
    printf("tid within signal handler: %i\n", tid);
	if (info && ucontext) {
		if (sig == SIGNAL && info->si_value.sival_int == DATA) {
			printf("Received correct signal and data!\n");
			sig_rec = 1;
		} else
			printf("Received wrong signal and/or data!\n");
	} else
		printf("Signal handling went wrong!\n");
}

int kontinue = 0;
static void *handle_thread(void *arg)
{
	int ret;

	tid = syscall(SYS_gettid);
    printf("tid of child thread: %i\n", tid);

	ret = sigaction(SIGNAL, sig_action, NULL);
	if (ret)
		printf("Failed to set sigaction for handler thread!\n");

	futex_wake(0);
	futex_wait(1);
}

static void verify_sigqueueinfo(void)
{
	tid = syscall(SYS_gettid);
    printf("tid within main thread: %i\n", tid);
	pthread_t thr;
	pthread_create(&thr, NULL, handle_thread, NULL);

	futex_wait(0);

	int ret;
	ret = syscall(__NR_rt_sigqueueinfo, tid, SIGNAL, uinfo);

	if (ret) {
		printf("rt_sigqueueinfo() failed");
		return;
	}

	futex_wake(1);
	ret = pthread_join(thr, NULL);
	if (ret) {
		printf("thread returned: %d\n", ret);
	}
	if (sig_rec)
		printf("rt_sigqueueinfo() was successful!");
}

static void setup(void)
{
	sig_action = malloc(sizeof(struct sigaction));

	memset(sig_action, 0, sizeof(*sig_action));
	sig_action->sa_sigaction = received_signal;
	sig_action->sa_flags = SA_SIGINFO;

	uinfo = malloc(sizeof(siginfo_t));

	memset(uinfo, 0, sizeof(*uinfo));
	uinfo->si_code = SI_QUEUE;
	uinfo->si_pid = getpid();
	uinfo->si_uid = getuid();
	uinfo->si_value.sival_int = DATA;

	sig_rec = 0;

	tst_futexes1 = malloc(sizeof(futex_t)*2);
}

static void cleanup(void)
{
	free(uinfo);
	free(sig_action);
	free(tst_futexes1);
}

void main(){
    setup();
    verify_sigqueueinfo();
    cleanup();
}

