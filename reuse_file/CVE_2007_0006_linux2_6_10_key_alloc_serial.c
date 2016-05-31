static inline void CVE_2007_0006_linux2_6_10_key_alloc_serial(struct key *key)
{
	struct rb_node *parent, **p;
	struct key *xkey;

	spin_lock(&key_serial_lock);

	/* propose a likely serial number and look for a hole for it in the
	 * serial number tree */
	key->serial = key_serial_next;
	if (key->serial < 3)
		key->serial = 3;
	key_serial_next = key->serial + 1;

	parent = NULL;
	p = &key_serial_tree.rb_node;

	while (*p) {
		parent = *p;
		xkey = rb_entry(parent, struct key, serial_node);

		if (key->serial < xkey->serial)
			p = &(*p)->rb_left;
		else if (key->serial > xkey->serial)
			p = &(*p)->rb_right;
		else
			goto serial_exists;
	}
	goto insert_here;

	/* we found a key with the proposed serial number - walk the tree from
	 * that point looking for the next unused serial number */
 serial_exists:
	for (;;) {
		key->serial = key_serial_next;
		if (key->serial < 2)
			key->serial = 2;
		key_serial_next = key->serial + 1;

		if (!parent->rb_parent)
			p = &key_serial_tree.rb_node;
		else if (parent->rb_parent->rb_left == parent)
			p = &parent->rb_parent->rb_left;
		else
			p = &parent->rb_parent->rb_right;

		parent = rb_next(parent);
		if (!parent)
			break;

		xkey = rb_entry(parent, struct key, serial_node);
		if (key->serial < xkey->serial)
			goto insert_here;
	}

	/* we've found a suitable hole - arrange for this key to occupy it */
 insert_here:
	rb_link_node(&key->serial_node, parent, p);
	rb_insert_color(&key->serial_node, &key_serial_tree);

	spin_unlock(&key_serial_lock);

}