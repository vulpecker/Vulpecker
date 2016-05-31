int CVE_2014_4656_linux2_6_16_snd_ctl_add(struct snd_card *card, struct snd_kcontrol *kcontrol)
{
	struct snd_ctl_elem_id id;
	unsigned int idx;

	snd_assert(card != NULL, return -EINVAL);
	if (! kcontrol)
		return -EINVAL;
	snd_assert(kcontrol->info != NULL, return -EINVAL);
	id = kcontrol->id;
	down_write(&card->controls_rwsem);
	if (snd_ctl_find_id(card, &id)) {
		up_write(&card->controls_rwsem);
		snd_ctl_free_one(kcontrol);
		snd_printd(KERN_ERR "control %i:%i:%i:%s:%i is already present\n",
					id.iface,
					id.device,
					id.subdevice,
					id.name,
					id.index);
		return -EBUSY;
	}
	if (snd_ctl_find_hole(card, kcontrol->count) < 0) {
		up_write(&card->controls_rwsem);
		snd_ctl_free_one(kcontrol);
		return -ENOMEM;
	}
	list_add_tail(&kcontrol->list, &card->controls);
	card->controls_count += kcontrol->count;
	kcontrol->id.numid = card->last_numid + 1;
	card->last_numid += kcontrol->count;
	up_write(&card->controls_rwsem);
	for (idx = 0; idx < kcontrol->count; idx++, id.index++, id.numid++)
		snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_ADD, &id);
	return 0;
}