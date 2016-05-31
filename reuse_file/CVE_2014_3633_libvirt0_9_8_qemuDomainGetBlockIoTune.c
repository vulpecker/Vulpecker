
static int
CVE_2014_3633_libvirt0_9_8_qemuDomainGetBlockIoTune(virDomainPtr dom,
                         const char *disk,
                         virTypedParameterPtr params,
                         int *nparams,
                         unsigned int flags)
{
    struct qemud_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    qemuDomainObjPrivatePtr priv;
    virDomainDefPtr persistentDef = NULL;
    virDomainBlockIoTuneInfo reply;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *device = NULL;
    int ret = -1;
    int i;
    bool isActive;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    qemuDriverLock(driver);
    virUUIDFormat(dom->uuid, uuidstr);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        qemuReportError(VIR_ERR_NO_DOMAIN,
                        _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if ((*nparams) == 0) {
        /* Current number of parameters supported by QEMU Block I/O Throttling */
        *nparams = QEMU_NB_BLOCK_IO_TUNE_PARAM;
        ret = 0;
        goto cleanup;
    }

    device = qemuDiskPathToAlias(vm, disk);

    if (!device) {
        goto cleanup;
    }

    if (qemuDomainObjBeginJobWithDriver(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    isActive = virDomainObjIsActive(vm);

    if (flags  == VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_AFFECT_LIVE;
        else
            flags = VIR_DOMAIN_AFFECT_CONFIG;
    }

    if (!isActive && (flags & VIR_DOMAIN_AFFECT_LIVE)) {
        qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("domain is not running"));
        goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        priv = vm->privateData;
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        ret = qemuMonitorGetBlockIoThrottle(priv->mon, device, &reply);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        if (ret < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!vm->persistent) {
            qemuReportError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("domain is transient"));
            goto endjob;
        }
        if (!(persistentDef = virDomainObjGetPersistentDef(driver->caps, vm)))
            goto endjob;

        int idx = virDomainDiskIndexByName(vm->def, disk, true);
        if (idx < 0)
            goto endjob;
        reply = persistentDef->disks[idx]->blkdeviotune;
    }

    for (i = 0; i < QEMU_NB_BLOCK_IO_TUNE_PARAM && i < *nparams; i++) {
        virTypedParameterPtr param = &params[i];
        param->value.ul = 0;
        param->type = VIR_TYPED_PARAM_ULLONG;

        switch(i) {
        case 0:
            if (virStrcpyStatic(param->field,
                                VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC) == NULL) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Field name '%s' too long"),
                                VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC);
                goto endjob;
            }
            param->value.ul = reply.total_bytes_sec;
            break;

        case 1:
            if (virStrcpyStatic(param->field,
                                VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC) == NULL) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Field name '%s' too long"),
                                VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC);
                goto endjob;
            }
            param->value.ul = reply.read_bytes_sec;
            break;

        case 2:
            if (virStrcpyStatic(param->field,
                                VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC) == NULL) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Field name '%s' too long"),
                                VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC);
                goto endjob;
            }
            param->value.ul = reply.write_bytes_sec;
            break;

        case 3:
            if (virStrcpyStatic(param->field,
                                VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC) == NULL) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Field name '%s' too long"),
                                VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC);
                goto endjob;
            }
            param->value.ul = reply.total_iops_sec;
            break;

        case 4:
            if (virStrcpyStatic(param->field,
                                VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC) == NULL) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Field name '%s' too long"),
                                VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC);
                goto endjob;
            }
            param->value.ul = reply.read_iops_sec;
            break;

        case 5:
            if (virStrcpyStatic(param->field,
                                VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC) == NULL) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Field name '%s' too long"),
                                VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC);
                goto endjob;
            }
            param->value.ul = reply.write_iops_sec;
            break;
        default:
            break;
        }
    }

    if (*nparams > QEMU_NB_BLOCK_IO_TUNE_PARAM)
        *nparams = QEMU_NB_BLOCK_IO_TUNE_PARAM;
    ret = 0;

endjob:
    if (qemuDomainObjEndJob(driver, vm) == 0)
        vm = NULL;

cleanup:
    VIR_FREE(device);
    if (vm)
        virDomainObjUnlock(vm);
    qemuDriverUnlock(driver);
    return ret;
}