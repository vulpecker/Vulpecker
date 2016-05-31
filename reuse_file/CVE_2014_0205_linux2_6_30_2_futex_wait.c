
static int CVE_2014_0205_linux2_6_30_2_futex_wait(u32 __user *uaddr, int fshared,
		      u32 val, ktime_t *abs_time, u32 bitset, int clockrt)
{
	struct task_struct *curr = current;
	struct restart_block *restart;
	DECLARE_WAITQUEUE(wait, curr);
	struct futex_hash_bucket *hb;
	struct futex_q q;
	u32 uval;
	int ret;
	struct hrtimer_sleeper t;
	int rem = 0;

	if (!bitset)
		return -EINVAL;

	q.pi_state = NULL;
	q.bitset = bitset;
retry:
	q.key = FUTEX_KEY_INIT;
	ret = get_futex_key(uaddr, fshared, &q.key, VERIFY_READ);
	if (unlikely(ret != 0))
		goto out;

retry_private:
	hb = queue_lock(&q);

	/*
	 * Access the page AFTER the hash-bucket is locked.
	 * Order is important:
	 *
	 *   Userspace waiter: val = var; if (cond(val)) CVE_2014_0205_linux2_6_30_2_futex_wait(&var, val);
	 *   Userspace waker:  if (cond(var)) { var = new; futex_wake(&var); }
	 *
	 * The basic logical guarantee of a futex is that it blocks ONLY
	 * if cond(var) is known to be true at the time of blocking, for
	 * any cond.  If we queued after testing *uaddr, that would open
	 * a race condition where we could block indefinitely with
	 * cond(var) false, which would violate the guarantee.
	 *
	 * A consequence is that CVE_2014_0205_linux2_6_30_2_futex_wait() can return zero and absorb
	 * a wakeup when *uaddr != val on entry to the syscall.  This is
	 * rare, but normal.
	 *
	 * For shared futexes, we hold the mmap semaphore, so the mapping
	 * cannot have changed since we looked it up in get_futex_key.
	 */
	ret = get_futex_value_locked(&uval, uaddr);

	if (unlikely(ret)) {
		queue_unlock(&q, hb);

		ret = get_user(uval, uaddr);
		if (ret)
			goto out_put_key;

		if (!fshared)
			goto retry_private;

		put_futex_key(fshared, &q.key);
		goto retry;
	}
	ret = -EWOULDBLOCK;
	if (unlikely(uval != val)) {
		queue_unlock(&q, hb);
		goto out_put_key;
	}

	/* Only actually queue if *uaddr contained val.  */
	queue_me(&q, hb);

	/*
	 * There might have been scheduling since the queue_me(), as we
	 * cannot hold a spinlock across the get_user() in case it
	 * faults, and we cannot just set TASK_INTERRUPTIBLE state when
	 * queueing ourselves into the futex hash.  This code thus has to
	 * rely on the futex_wake() code removing us from hash when it
	 * wakes us up.
	 */

	/* add_wait_queue is the barrier after __set_current_state. */
	__set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&q.waiter, &wait);
	/*
	 * !plist_node_empty() is safe here without any lock.
	 * q.lock_ptr != 0 is not safe, because of ordering against wakeup.
	 */
	if (likely(!plist_node_empty(&q.list))) {
		if (!abs_time)
			schedule();
		else {
			hrtimer_init_on_stack(&t.timer,
					      clockrt ? CLOCK_REALTIME :
					      CLOCK_MONOTONIC,
					      HRTIMER_MODE_ABS);
			hrtimer_init_sleeper(&t, current);
			hrtimer_set_expires_range_ns(&t.timer, *abs_time,
						     current->timer_slack_ns);

			hrtimer_start_expires(&t.timer, HRTIMER_MODE_ABS);
			if (!hrtimer_active(&t.timer))
				t.task = NULL;

			/*
			 * the timer could have already expired, in which
			 * case current would be flagged for rescheduling.
			 * Don't bother calling schedule.
			 */
			if (likely(t.task))
				schedule();

			hrtimer_cancel(&t.timer);

			/* Flag if a timeout occured */
			rem = (t.task == NULL);

			destroy_hrtimer_on_stack(&t.timer);
		}
	}
	__set_current_state(TASK_RUNNING);

	/*
	 * NOTE: we don't remove ourselves from the waitqueue because
	 * we are the only user of it.
	 */

	/* If we were woken (and unqueued), we succeeded, whatever. */
	ret = 0;
	if (!unqueue_me(&q))
		goto out_put_key;
	ret = -ETIMEDOUT;
	if (rem)
		goto out_put_key;

	/*
	 * We expect signal_pending(current), but another thread may
	 * have handled it for us already.
	 */
	ret = -ERESTARTSYS;
	if (!abs_time)
		goto out_put_key;

	restart = &current_thread_info()->restart_block;
	restart->fn = CVE_2014_0205_linux2_6_30_2_futex_wait_restart;
	restart->futex.uaddr = (u32 *)uaddr;
	restart->futex.val = val;
	restart->futex.time = abs_time->tv64;
	restart->futex.bitset = bitset;
	restart->futex.flags = 0;

	if (fshared)
		restart->futex.flags |= FLAGS_SHARED;
	if (clockrt)
		restart->futex.flags |= FLAGS_CLOCKRT;

	ret = -ERESTART_RESTARTBLOCK;

out_put_key:
	put_futex_key(fshared, &q.key);
out:
	return ret;
}