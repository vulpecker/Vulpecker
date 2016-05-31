
static int CVE_2010_1083_linux2_6_23_processcompl(struct async *as, void __user * __user *arg)
{
	struct urb *urb = as->urb;
	struct usbdevfs_urb __user *userurb = as->userurb;
	void __user *addr = as->userurb;
	unsigned int i;

	if (as->userbuffer)
		if (copy_to_user(as->userbuffer, urb->transfer_buffer, urb->transfer_buffer_length))
			return -EFAULT;
	if (put_user(urb->status, &userurb->status))
		return -EFAULT;
	if (put_user(urb->actual_length, &userurb->actual_length))
		return -EFAULT;
	if (put_user(urb->error_count, &userurb->error_count))
		return -EFAULT;

	if (usb_pipeisoc(urb->pipe)) {
		for (i = 0; i < urb->number_of_packets; i++) {
			if (put_user(urb->iso_frame_desc[i].actual_length,
				     &userurb->iso_frame_desc[i].actual_length))
				return -EFAULT;
			if (put_user(urb->iso_frame_desc[i].status,
				     &userurb->iso_frame_desc[i].status))
				return -EFAULT;
		}
	}

	free_async(as);

	if (put_user(addr, (void __user * __user *)arg))
		return -EFAULT;
	return 0;
}