#ifndef MM_SLEEP_LOCK_H
#define MM_SLEEP_LOCK_H

/*
 * machinarium.
 *
 * cooperative multitasking engine.
*/

typedef unsigned int mm_sleeplock_t;

#if defined(__x86_64__) || defined(__i386) || defined(_X86_)
#  define MM_SLEEPLOCK_BACKOFF __asm__ ("pause")
#else
#  define MM_SLEEPLOCK_BACKOFF
#endif

static inline void
mm_sleeplock_init(mm_sleeplock_t *lock)
{
	*lock = 0;
}

static inline void
mm_sleeplock_lock(mm_sleeplock_t *lock)
{
	if (__sync_lock_test_and_set(lock, 1) != 0) {
		unsigned int spin_count = 0U;
		for (;;) {
			MM_SLEEPLOCK_BACKOFF;
			if (*lock == 0U && __sync_lock_test_and_set(lock, 1) == 0)
				break;
			if (++spin_count > 30U)
				usleep(1);
		}
	}
}

static inline void
mm_sleeplock_unlock(mm_sleeplock_t *lock)
{
	__sync_lock_release(lock);
}

typedef int pthread_spinlock_t;
#define UNUSED(x) (void)(x)

int pthread_spin_init(pthread_spinlock_t *lock, int pshared) {
    UNUSED(pshared);
	__asm__ __volatile__ ("" ::: "memory");
	*lock = 0;
	return 0;
}

int pthread_spin_destroy(pthread_spinlock_t *lock) {
    UNUSED(lock);
	return 0;
}

int pthread_spin_lock(pthread_spinlock_t *lock) {
	while (1) {
		int i;
		for (i=0; i < 10000; i++) {
			if (__sync_bool_compare_and_swap(lock, 0, 1)) {
				return 0;
			}
		}
		sched_yield();
	}
}

int pthread_spin_trylock(pthread_spinlock_t *lock) {
	if (__sync_bool_compare_and_swap(lock, 0, 1)) {
		return 0;
	}
	return EBUSY;
}

int pthread_spin_unlock(pthread_spinlock_t *lock) {
	__asm__ __volatile__ ("" ::: "memory");
	*lock = 0;
	return 0;
}

#endif /* MM_SLEEP_LOCK_H */
