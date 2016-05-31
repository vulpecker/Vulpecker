static int CVE_2010_1085_linux2_6_32_21_azx_position_ok(struct azx *chip, struct azx_dev *azx_dev)
{
	unsigned int pos;

	if (azx_dev->start_flag &&
	    time_before_eq(jiffies, azx_dev->start_jiffies))
		return -1;	/* bogus (too early) interrupt */
	azx_dev->start_flag = 0;

	pos = azx_get_position(chip, azx_dev);
	if (chip->position_fix == POS_FIX_AUTO) {
		if (!pos) {
			printk(KERN_WARNING
			       "hda-intel: Invalid position buffer, "
			       "using LPIB read method instead.\n");
			chip->position_fix = POS_FIX_LPIB;
			pos = azx_get_position(chip, azx_dev);
		} else
			chip->position_fix = POS_FIX_POSBUF;
	}

	if (!bdl_pos_adj[chip->dev_index])
		return 1; /* no delayed ack */
	if (WARN_ONCE(!azx_dev->period_bytes,
		      "hda-intel: zero azx_dev->period_bytes"))
		return 0; /* this shouldn't happen! */
	if (pos % azx_dev->period_bytes > azx_dev->period_bytes / 2)
		return 0; /* NG - it's below the period boundary */
	return 1; /* OK, it's fine */
}