static long
CVE_2011_1495_linux2_6_34_2__ctl_do_mpt_command(struct MPT2SAS_ADAPTER *ioc,
    struct mpt2_ioctl_command karg, void __user *mf, enum block_state state)
{
	MPI2RequestHeader_t *mpi_request;
	MPI2DefaultReply_t *mpi_reply;
	u32 ioc_state;
	u16 ioc_status;
	u16 smid;
	unsigned long timeout, timeleft;
	u8 issue_reset;
	u32 sz;
	void *psge;
	void *priv_sense = NULL;
	void *data_out = NULL;
	dma_addr_t data_out_dma;
	size_t data_out_sz = 0;
	void *data_in = NULL;
	dma_addr_t data_in_dma;
	size_t data_in_sz = 0;
	u32 sgl_flags;
	long ret;
	u16 wait_state_count;

	issue_reset = 0;

	if (state == NON_BLOCKING && !mutex_trylock(&ioc->ctl_cmds.mutex))
		return -EAGAIN;
	else if (mutex_lock_interruptible(&ioc->ctl_cmds.mutex))
		return -ERESTARTSYS;

	if (ioc->ctl_cmds.status != MPT2_CMD_NOT_USED) {
		printk(MPT2SAS_ERR_FMT "%s: ctl_cmd in use\n",
		    ioc->name, __func__);
		ret = -EAGAIN;
		goto out;
	}

	wait_state_count = 0;
	ioc_state = mpt2sas_base_get_iocstate(ioc, 1);
	while (ioc_state != MPI2_IOC_STATE_OPERATIONAL) {
		if (wait_state_count++ == 10) {
			printk(MPT2SAS_ERR_FMT
			    "%s: failed due to ioc not operational\n",
			    ioc->name, __func__);
			ret = -EFAULT;
			goto out;
		}
		ssleep(1);
		ioc_state = mpt2sas_base_get_iocstate(ioc, 1);
		printk(MPT2SAS_INFO_FMT "%s: waiting for "
		    "operational state(count=%d)\n", ioc->name,
		    __func__, wait_state_count);
	}
	if (wait_state_count)
		printk(MPT2SAS_INFO_FMT "%s: ioc is operational\n",
		    ioc->name, __func__);

	smid = mpt2sas_base_get_smid_scsiio(ioc, ioc->ctl_cb_idx, NULL);
	if (!smid) {
		printk(MPT2SAS_ERR_FMT "%s: failed obtaining a smid\n",
		    ioc->name, __func__);
		ret = -EAGAIN;
		goto out;
	}

	ret = 0;
	ioc->ctl_cmds.status = MPT2_CMD_PENDING;
	memset(ioc->ctl_cmds.reply, 0, ioc->reply_sz);
	mpi_request = mpt2sas_base_get_msg_frame(ioc, smid);
	ioc->ctl_cmds.smid = smid;
	data_out_sz = karg.data_out_size;
	data_in_sz = karg.data_in_size;

	/* copy in request message frame from user */
	if (copy_from_user(mpi_request, mf, karg.data_sge_offset*4)) {
		printk(KERN_ERR "failure at %s:%d/%s()!\n", __FILE__, __LINE__,
		    __func__);
		ret = -EFAULT;
		mpt2sas_base_free_smid(ioc, smid);
		goto out;
	}

	if (mpi_request->Function == MPI2_FUNCTION_SCSI_IO_REQUEST ||
	    mpi_request->Function == MPI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH) {
		if (!mpi_request->FunctionDependent1 ||
		    mpi_request->FunctionDependent1 >
		    cpu_to_le16(ioc->facts.MaxDevHandle)) {
			ret = -EINVAL;
			mpt2sas_base_free_smid(ioc, smid);
			goto out;
		}
	}

	/* obtain dma-able memory for data transfer */
	if (data_out_sz) /* WRITE */ {
		data_out = pci_alloc_consistent(ioc->pdev, data_out_sz,
		    &data_out_dma);
		if (!data_out) {
			printk(KERN_ERR "failure at %s:%d/%s()!\n", __FILE__,
			    __LINE__, __func__);
			ret = -ENOMEM;
			mpt2sas_base_free_smid(ioc, smid);
			goto out;
		}
		if (copy_from_user(data_out, karg.data_out_buf_ptr,
			data_out_sz)) {
			printk(KERN_ERR "failure at %s:%d/%s()!\n", __FILE__,
			    __LINE__, __func__);
			ret =  -EFAULT;
			mpt2sas_base_free_smid(ioc, smid);
			goto out;
		}
	}

	if (data_in_sz) /* READ */ {
		data_in = pci_alloc_consistent(ioc->pdev, data_in_sz,
		    &data_in_dma);
		if (!data_in) {
			printk(KERN_ERR "failure at %s:%d/%s()!\n", __FILE__,
			    __LINE__, __func__);
			ret = -ENOMEM;
			mpt2sas_base_free_smid(ioc, smid);
			goto out;
		}
	}

	/* add scatter gather elements */
	psge = (void *)mpi_request + (karg.data_sge_offset*4);

	if (!data_out_sz && !data_in_sz) {
		mpt2sas_base_build_zero_len_sge(ioc, psge);
	} else if (data_out_sz && data_in_sz) {
		/* WRITE sgel first */
		sgl_flags = (MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
		    MPI2_SGE_FLAGS_END_OF_BUFFER | MPI2_SGE_FLAGS_HOST_TO_IOC);
		sgl_flags = sgl_flags << MPI2_SGE_FLAGS_SHIFT;
		ioc->base_add_sg_single(psge, sgl_flags |
		    data_out_sz, data_out_dma);

		/* incr sgel */
		psge += ioc->sge_size;

		/* READ sgel last */
		sgl_flags = (MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
		    MPI2_SGE_FLAGS_LAST_ELEMENT | MPI2_SGE_FLAGS_END_OF_BUFFER |
		    MPI2_SGE_FLAGS_END_OF_LIST);
		sgl_flags = sgl_flags << MPI2_SGE_FLAGS_SHIFT;
		ioc->base_add_sg_single(psge, sgl_flags |
		    data_in_sz, data_in_dma);
	} else if (data_out_sz) /* WRITE */ {
		sgl_flags = (MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
		    MPI2_SGE_FLAGS_LAST_ELEMENT | MPI2_SGE_FLAGS_END_OF_BUFFER |
		    MPI2_SGE_FLAGS_END_OF_LIST | MPI2_SGE_FLAGS_HOST_TO_IOC);
		sgl_flags = sgl_flags << MPI2_SGE_FLAGS_SHIFT;
		ioc->base_add_sg_single(psge, sgl_flags |
		    data_out_sz, data_out_dma);
	} else if (data_in_sz) /* READ */ {
		sgl_flags = (MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
		    MPI2_SGE_FLAGS_LAST_ELEMENT | MPI2_SGE_FLAGS_END_OF_BUFFER |
		    MPI2_SGE_FLAGS_END_OF_LIST);
		sgl_flags = sgl_flags << MPI2_SGE_FLAGS_SHIFT;
		ioc->base_add_sg_single(psge, sgl_flags |
		    data_in_sz, data_in_dma);
	}

	/* send command to firmware */
#ifdef CONFIG_SCSI_MPT2SAS_LOGGING
	_ctl_display_some_debug(ioc, smid, "ctl_request", NULL);
#endif

	switch (mpi_request->Function) {
	case MPI2_FUNCTION_SCSI_IO_REQUEST:
	case MPI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH:
	{
		Mpi2SCSIIORequest_t *scsiio_request =
		    (Mpi2SCSIIORequest_t *)mpi_request;
		scsiio_request->SenseBufferLowAddress =
		    mpt2sas_base_get_sense_buffer_dma(ioc, smid);
		priv_sense = mpt2sas_base_get_sense_buffer(ioc, smid);
		memset(priv_sense, 0, SCSI_SENSE_BUFFERSIZE);
		mpt2sas_base_put_smid_scsi_io(ioc, smid,
		    le16_to_cpu(mpi_request->FunctionDependent1));
		break;
	}
	case MPI2_FUNCTION_SCSI_TASK_MGMT:
	{
		Mpi2SCSITaskManagementRequest_t *tm_request =
		    (Mpi2SCSITaskManagementRequest_t *)mpi_request;

		if (tm_request->TaskType ==
		    MPI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK ||
		    tm_request->TaskType ==
		    MPI2_SCSITASKMGMT_TASKTYPE_QUERY_TASK) {
			if (_ctl_set_task_mid(ioc, &karg, tm_request)) {
				mpt2sas_base_free_smid(ioc, smid);
				goto out;
			}
		}

		mutex_lock(&ioc->tm_cmds.mutex);
		mpt2sas_scsih_set_tm_flag(ioc, le16_to_cpu(
		    tm_request->DevHandle));
		mpt2sas_base_put_smid_hi_priority(ioc, smid);
		break;
	}
	case MPI2_FUNCTION_SMP_PASSTHROUGH:
	{
		Mpi2SmpPassthroughRequest_t *smp_request =
		    (Mpi2SmpPassthroughRequest_t *)mpi_request;
		u8 *data;

		/* ioc determines which port to use */
		smp_request->PhysicalPort = 0xFF;
		if (smp_request->PassthroughFlags &
		    MPI2_SMP_PT_REQ_PT_FLAGS_IMMEDIATE)
			data = (u8 *)&smp_request->SGL;
		else
			data = data_out;

		if (data[1] == 0x91 && (data[10] == 1 || data[10] == 2)) {
			ioc->ioc_link_reset_in_progress = 1;
			ioc->ignore_loginfos = 1;
		}
		mpt2sas_base_put_smid_default(ioc, smid);
		break;
	}
	case MPI2_FUNCTION_SAS_IO_UNIT_CONTROL:
	{
		Mpi2SasIoUnitControlRequest_t *sasiounit_request =
		    (Mpi2SasIoUnitControlRequest_t *)mpi_request;

		if (sasiounit_request->Operation == MPI2_SAS_OP_PHY_HARD_RESET
		    || sasiounit_request->Operation ==
		    MPI2_SAS_OP_PHY_LINK_RESET) {
			ioc->ioc_link_reset_in_progress = 1;
			ioc->ignore_loginfos = 1;
		}
		mpt2sas_base_put_smid_default(ioc, smid);
		break;
	}
	default:
		mpt2sas_base_put_smid_default(ioc, smid);
		break;
	}

	if (karg.timeout < MPT2_IOCTL_DEFAULT_TIMEOUT)
		timeout = MPT2_IOCTL_DEFAULT_TIMEOUT;
	else
		timeout = karg.timeout;
	init_completion(&ioc->ctl_cmds.done);
	timeleft = wait_for_completion_timeout(&ioc->ctl_cmds.done,
	    timeout*HZ);
	if (mpi_request->Function == MPI2_FUNCTION_SCSI_TASK_MGMT) {
		Mpi2SCSITaskManagementRequest_t *tm_request =
		    (Mpi2SCSITaskManagementRequest_t *)mpi_request;
		mutex_unlock(&ioc->tm_cmds.mutex);
		mpt2sas_scsih_clear_tm_flag(ioc, le16_to_cpu(
		    tm_request->DevHandle));
	} else if ((mpi_request->Function == MPI2_FUNCTION_SMP_PASSTHROUGH ||
	    mpi_request->Function == MPI2_FUNCTION_SAS_IO_UNIT_CONTROL) &&
		ioc->ioc_link_reset_in_progress) {
		ioc->ioc_link_reset_in_progress = 0;
		ioc->ignore_loginfos = 0;
	}
	if (!(ioc->ctl_cmds.status & MPT2_CMD_COMPLETE)) {
		printk(MPT2SAS_ERR_FMT "%s: timeout\n", ioc->name,
		    __func__);
		_debug_dump_mf(mpi_request, karg.data_sge_offset);
		if (!(ioc->ctl_cmds.status & MPT2_CMD_RESET))
			issue_reset = 1;
		goto issue_host_reset;
	}

	mpi_reply = ioc->ctl_cmds.reply;
	ioc_status = le16_to_cpu(mpi_reply->IOCStatus) & MPI2_IOCSTATUS_MASK;

#ifdef CONFIG_SCSI_MPT2SAS_LOGGING
	if (mpi_reply->Function == MPI2_FUNCTION_SCSI_TASK_MGMT &&
	    (ioc->logging_level & MPT_DEBUG_TM)) {
		Mpi2SCSITaskManagementReply_t *tm_reply =
		    (Mpi2SCSITaskManagementReply_t *)mpi_reply;

		printk(MPT2SAS_DEBUG_FMT "TASK_MGMT: "
		    "IOCStatus(0x%04x), IOCLogInfo(0x%08x), "
		    "TerminationCount(0x%08x)\n", ioc->name,
		    le16_to_cpu(tm_reply->IOCStatus),
		    le32_to_cpu(tm_reply->IOCLogInfo),
		    le32_to_cpu(tm_reply->TerminationCount));
	}
#endif
	/* copy out xdata to user */
	if (data_in_sz) {
		if (copy_to_user(karg.data_in_buf_ptr, data_in,
		    data_in_sz)) {
			printk(KERN_ERR "failure at %s:%d/%s()!\n", __FILE__,
			    __LINE__, __func__);
			ret = -ENODATA;
			goto out;
		}
	}

	/* copy out reply message frame to user */
	if (karg.max_reply_bytes) {
		sz = min_t(u32, karg.max_reply_bytes, ioc->reply_sz);
		if (copy_to_user(karg.reply_frame_buf_ptr, ioc->ctl_cmds.reply,
		    sz)) {
			printk(KERN_ERR "failure at %s:%d/%s()!\n", __FILE__,
			    __LINE__, __func__);
			ret = -ENODATA;
			goto out;
		}
	}

	/* copy out sense to user */
	if (karg.max_sense_bytes && (mpi_request->Function ==
	    MPI2_FUNCTION_SCSI_IO_REQUEST || mpi_request->Function ==
	    MPI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH)) {
		sz = min_t(u32, karg.max_sense_bytes, SCSI_SENSE_BUFFERSIZE);
		if (copy_to_user(karg.sense_data_ptr, priv_sense, sz)) {
			printk(KERN_ERR "failure at %s:%d/%s()!\n", __FILE__,
			    __LINE__, __func__);
			ret = -ENODATA;
			goto out;
		}
	}

 issue_host_reset:
	if (issue_reset) {
		ret = -ENODATA;
		if ((mpi_request->Function == MPI2_FUNCTION_SCSI_IO_REQUEST ||
		    mpi_request->Function ==
		    MPI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH)) {
			printk(MPT2SAS_INFO_FMT "issue target reset: handle "
			    "= (0x%04x)\n", ioc->name,
			    mpi_request->FunctionDependent1);
			mpt2sas_halt_firmware(ioc);
			mutex_lock(&ioc->tm_cmds.mutex);
			mpt2sas_scsih_issue_tm(ioc,
			    mpi_request->FunctionDependent1, 0,
			    MPI2_SCSITASKMGMT_TASKTYPE_TARGET_RESET, 0, 10);
			ioc->tm_cmds.status = MPT2_CMD_NOT_USED;
			mutex_unlock(&ioc->tm_cmds.mutex);
		} else
			mpt2sas_base_hard_reset_handler(ioc, CAN_SLEEP,
			    FORCE_BIG_HAMMER);
	}

 out:

	/* free memory associated with sg buffers */
	if (data_in)
		pci_free_consistent(ioc->pdev, data_in_sz, data_in,
		    data_in_dma);

	if (data_out)
		pci_free_consistent(ioc->pdev, data_out_sz, data_out,
		    data_out_dma);

	ioc->ctl_cmds.status = MPT2_CMD_NOT_USED;
	mutex_unlock(&ioc->ctl_cmds.mutex);
	return ret;
}