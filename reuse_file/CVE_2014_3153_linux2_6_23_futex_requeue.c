static int CVE_2014_3153_linux2_6_23_futex_requeue(u32 __user *uaddr1, struct rw_semaphore *fshared,
			 u32 __user *uaddr2,
			 int nr_wake, int nr_requeue, u32 *cmpval)
{
	union futex_key key1, key2;
	struct futex_hash_bucket *hb1, *hb2;
	struct plist_head *head1;
	struct futex_q *this, *next;
	int ret, drop_count = 0;

 retry:
	futex_lock_mm(fshared);

	ret = get_futex_key(uaddr1, fshared, &key1);
	if (unlikely(ret != 0))
		goto out;
	ret = get_futex_key(uaddr2, fshared, &key2);
	if (unlikely(ret != 0))
		goto out;

	hb1 = hash_futex(&key1);
	hb2 = hash_futex(&key2);

	double_lock_hb(hb1, hb2);

	if (likely(cmpval != NULL)) {
		u32 curval;

		ret = get_futex_value_locked(&curval, uaddr1);

		if (unlikely(ret)) {
			spin_unlock(&hb1->lock);
			if (hb1 != hb2)
				spin_unlock(&hb2->lock);

			/*
			 * If we would have faulted, release mmap_sem, fault
			 * it in and start all over again.
			 */
			futex_unlock_mm(fshared);

			ret = get_user(curval, uaddr1);

			if (!ret)
				goto retry;

			return ret;
		}
		if (curval != *cmpval) {
			ret = -EAGAIN;
			goto out_unlock;
		}
	}

	head1 = &hb1->chain;
	plist_for_each_entry_safe(this, next, head1, list) {
		if (!match_futex (&this->key, &key1))
			continue;
		if (++ret <= nr_wake) {
			wake_futex(this);
		} else {
			/*
			 * If key1 and key2 hash to the same bucket, no need to
			 * requeue.
			 */
			if (likely(head1 != &hb2->chain)) {
				plist_del(&this->list, &hb1->chain);
				plist_add(&this->list, &hb2->chain);
				this->lock_ptr = &hb2->lock;
#ifdef CONFIG_DEBUG_PI_LIST
				this->list.plist.lock = &hb2->lock;
#endif
			}
			this->key = key2;
			get_futex_key_refs(&key2);
			drop_count++;

			if (ret - nr_wake >= nr_requeue)
				break;
		}
	}

out_unlock:
	spin_unlock(&hb1->lock);
	if (hb1 != hb2)
		spin_unlock(&hb2->lock);

	/* drop_futex_key_refs() must be called outside the spinlocks. */
	while (--drop_count >= 0)
		drop_futex_key_refs(&key1);

out:
	futex_unlock_mm(fshared);
	return ret;
}