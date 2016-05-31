

static int
CVE_2013_6456_libvirt1_1_1_lxcDomainDetachDeviceHostdevUSBLive(virLXCDriverPtr driver,
                                    virDomainObjPtr vm,
                                    virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevDefPtr def = NULL;
    int idx, ret = -1;
    char *dst = NULL;
    char *vroot;
    virUSBDevicePtr usb = NULL;

    if ((idx = virDomainHostdevFind(vm->def,
                                    dev->data.hostdev,
                                    &def)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("usb device not found"));
        goto cleanup;
    }

    if (virAsprintf(&vroot, "/proc/%llu/root",
                    (unsigned long long)priv->initpid) < 0)
        goto cleanup;

    if (virAsprintf(&dst, "%s/dev/bus/usb/%03d/%03d",
                    vroot,
                    def->source.subsys.u.usb.bus,
                    def->source.subsys.u.usb.device) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    if (!(usb = virUSBDeviceNew(def->source.subsys.u.usb.bus,
                                def->source.subsys.u.usb.device, vroot)))
        goto cleanup;

    VIR_DEBUG("Unlinking %s", dst);
    if (unlink(dst) < 0 && errno != ENOENT) {
        virDomainAuditHostdev(vm, def, "detach", false);
        virReportSystemError(errno,
                             _("Unable to remove device %s"), dst);
        goto cleanup;
    }
    virDomainAuditHostdev(vm, def, "detach", true);

    if (virUSBDeviceFileIterate(usb,
                                virLXCTeardownHostUsbDeviceCgroup,
                                &priv->cgroup) < 0)
        VIR_WARN("cannot deny device %s for domain %s",
                 dst, vm->def->name);

    virObjectLock(driver->activeUsbHostdevs);
    virUSBDeviceListDel(driver->activeUsbHostdevs, usb);
    virObjectUnlock(driver->activeUsbHostdevs);

    virDomainHostdevRemove(vm->def, idx);
    virDomainHostdevDefFree(def);

    ret = 0;

cleanup:
    virUSBDeviceFree(usb);
    VIR_FREE(dst);
    return ret;
}