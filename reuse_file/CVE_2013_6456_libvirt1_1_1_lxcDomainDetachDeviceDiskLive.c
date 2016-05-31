

static int
CVE_2013_6456_libvirt1_1_1_lxcDomainDetachDeviceDiskLive(virDomainObjPtr vm,
                              virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainDiskDefPtr def = NULL;
    int idx, ret = -1;
    char *dst = NULL;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        goto cleanup;
    }

    if ((idx = virDomainDiskIndexByName(vm->def,
                                        dev->data.disk->dst,
                                        false)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("disk %s not found"), dev->data.disk->dst);
        goto cleanup;
    }

    def = vm->def->disks[idx];

    if (virAsprintf(&dst, "/proc/%llu/root/dev/%s",
                    (unsigned long long)priv->initpid, def->dst) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    VIR_DEBUG("Unlinking %s (backed by %s)", dst, def->src);
    if (unlink(dst) < 0 && errno != ENOENT) {
        virDomainAuditDisk(vm, def->src, NULL, "detach", false);
        virReportSystemError(errno,
                             _("Unable to remove device %s"), dst);
        goto cleanup;
    }
    virDomainAuditDisk(vm, def->src, NULL, "detach", true);

    if (virCgroupDenyDevicePath(priv->cgroup, def->src, VIR_CGROUP_DEVICE_RWM) != 0)
        VIR_WARN("cannot deny device %s for domain %s",
                 def->src, vm->def->name);

    virDomainDiskRemove(vm->def, idx);
    virDomainDiskDefFree(def);

    ret = 0;

cleanup:
    VIR_FREE(dst);
    return ret;
}