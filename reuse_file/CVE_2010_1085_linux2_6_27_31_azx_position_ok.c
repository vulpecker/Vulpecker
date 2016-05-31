static int CVE_2010_1085_linux2_6_27_31_azx_position_ok(struct azx *chip, struct azx_dev *azx_dev)
{
	unsigned int pos;

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

	if (pos % azx_dev->period_bytes > azx_dev->period_bytes / 2)
		return 0; /* NG - it's below the period boundary */
	return 1; /* OK, it's fine */
}