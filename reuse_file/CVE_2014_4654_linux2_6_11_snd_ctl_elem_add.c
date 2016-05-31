
static int CVE_2014_4654_linux2_6_11_snd_ctl_elem_add(snd_ctl_file_t *file, snd_ctl_elem_info_t __user *_info, int replace)
{
	snd_card_t *card = file->card;
	snd_ctl_elem_info_t info;
	snd_kcontrol_t kctl, *_kctl;
	unsigned int access;
	long private_size, extra_size;
	struct user_element *ue;
	int idx, err;
	
	if (card->user_ctl_count >= MAX_USER_CONTROLS)
		return -ENOMEM;
	if (copy_from_user(&info, _info, sizeof(info)))
		return -EFAULT;
	if (info.count > 1024)
		return -EINVAL;
	access = info.access == 0 ? SNDRV_CTL_ELEM_ACCESS_READWRITE :
		(info.access & (SNDRV_CTL_ELEM_ACCESS_READWRITE|SNDRV_CTL_ELEM_ACCESS_INACTIVE));
	info.id.numid = 0;
	memset(&kctl, 0, sizeof(kctl));
	down_write(&card->controls_rwsem);
	_kctl = snd_ctl_find_id(card, &info.id);
	err = 0;
	if (_kctl) {
		if (replace)
			err = snd_ctl_remove(card, _kctl);
		else
			err = -EBUSY;
	} else {
		if (replace)
			err = -ENOENT;
	}
	up_write(&card->controls_rwsem);
	if (err < 0)
		return err;
	memcpy(&kctl.id, &info.id, sizeof(info.id));
	kctl.count = info.owner ? info.owner : 1;
	access |= SNDRV_CTL_ELEM_ACCESS_USER;
	kctl.info = snd_ctl_elem_user_info;
	if (access & SNDRV_CTL_ELEM_ACCESS_READ)
		kctl.get = snd_ctl_elem_user_get;
	if (access & SNDRV_CTL_ELEM_ACCESS_WRITE)
		kctl.put = snd_ctl_elem_user_put;
	extra_size = 0;
	switch (info.type) {
	case SNDRV_CTL_ELEM_TYPE_BOOLEAN:
		private_size = sizeof(char);
		if (info.count > 128)
			return -EINVAL;
		break;
	case SNDRV_CTL_ELEM_TYPE_INTEGER:
		private_size = sizeof(long);
		if (info.count > 128)
			return -EINVAL;
		break;
	case SNDRV_CTL_ELEM_TYPE_INTEGER64:
		private_size = sizeof(long long);
		if (info.count > 64)
			return -EINVAL;
		break;
	case SNDRV_CTL_ELEM_TYPE_ENUMERATED:
		private_size = sizeof(unsigned int);
		if (info.count > 128)
			return -EINVAL;
		if (info.value.enumerated.items > 128)
			return -EINVAL;
		extra_size = info.value.enumerated.items * 64;
		break;
	case SNDRV_CTL_ELEM_TYPE_BYTES:
		private_size = sizeof(unsigned char);
		if (info.count > 512)
			return -EINVAL;
		break;
	case SNDRV_CTL_ELEM_TYPE_IEC958:
		private_size = sizeof(struct sndrv_aes_iec958);
		if (info.count != 1)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
	private_size *= info.count;
	ue = kcalloc(1, sizeof(struct user_element) + private_size + extra_size, GFP_KERNEL);
	if (ue == NULL)
		return -ENOMEM;
	ue->info = info;
	ue->elem_data = (char *)ue + sizeof(ue);
	ue->elem_data_size = private_size;
	if (extra_size) {
		ue->priv_data = (char *)ue + sizeof(ue) + private_size;
		ue->priv_data_size = extra_size;
		if (ue->info.type == SNDRV_CTL_ELEM_TYPE_ENUMERATED) {
			if (copy_from_user(ue->priv_data, *(char __user **)info.value.enumerated.name, extra_size))
				return -EFAULT;
		}
	}
	kctl.private_free = snd_ctl_elem_user_free;
	_kctl = snd_ctl_new(&kctl, access);
	if (_kctl == NULL) {
		kfree(_kctl->private_data);
		return -ENOMEM;
	}
	_kctl->private_data = ue;
	for (idx = 0; idx < _kctl->count; idx++)
		_kctl->vd[idx].owner = file;
	err = snd_ctl_add(card, _kctl);
	if (err < 0) {
		snd_ctl_free_one(_kctl);
		return err;
	}

	down_write(&card->controls_rwsem);
	card->user_ctl_count++;
	up_write(&card->controls_rwsem);

	return 0;
}