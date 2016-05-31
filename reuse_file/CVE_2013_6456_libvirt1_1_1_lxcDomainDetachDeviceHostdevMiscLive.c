

static int
CVE_2013_6456_libvirt1_1_1_lxcDomainDetachDeviceHostdevMiscLive(virDomainObjPtr vm,
                                     virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevDefPtr def = NULL;
    int idx, ret = -1;
    char *dst = NULL;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        goto cleanup;
    }

    if ((idx = virDomainHostdevFind(vm->def,
                                    dev->data.hostdev,
                                    &def)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("hostdev %s not found"),
                       dev->data.hostdev->source.caps.u.misc.chardev);
        goto cleanup;
    }

    if (virAsprintf(&dst, "/proc/%llu/root/%s",
                    (unsigned long long)priv->initpid,
                    def->source.caps.u.misc.chardev) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    VIR_DEBUG("Unlinking %s", dst);
    if (unlink(dst) < 0 && errno != ENOENT) {
        virDomainAuditHostdev(vm, def, "detach", false);
        virReportSystemError(errno,
                             _("Unable to remove device %s"), dst);
        goto cleanup;
    }
    virDomainAuditHostdev(vm, def, "detach", true);

    if (virCgroupDenyDevicePath(priv->cgroup, def->source.caps.u.misc.chardev, VIR_CGROUP_DEVICE_RWM) != 0)
        VIR_WARN("cannot deny device %s for domain %s",
                 def->source.caps.u.misc.chardev, vm->def->name);

    virDomainHostdevRemove(vm->def, idx);
    virDomainHostdevDefFree(def);

    ret = 0;

cleanup:
    VIR_FREE(dst);
    return ret;
}