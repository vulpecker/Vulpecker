
static int
CVE_2013_6436_libvirt1_1_0_lxcDomainGetMemoryParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    int i;
    virDomainObjPtr vm = NULL;
    unsigned long long val;
    int ret = -1;
    int rc;
    virLXCDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    lxcDriverLock(driver);
    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);

    if (vm == NULL) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    priv = vm->privateData;

    if (virDomainGetMemoryParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if ((*nparams) == 0) {
        /* Current number of memory parameters supported by cgroups */
        *nparams = LXC_NB_MEM_PARAM;
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < LXC_NB_MEM_PARAM && i < *nparams; i++) {
        virTypedParameterPtr param = &params[i];
        val = 0;

        switch (i) {
        case 0: /* fill memory hard limit here */
            rc = virCgroupGetMemoryHardLimit(priv->cgroup, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get memory hard limit"));
                goto cleanup;
            }
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;
        case 1: /* fill memory soft limit here */
            rc = virCgroupGetMemorySoftLimit(priv->cgroup, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get memory soft limit"));
                goto cleanup;
            }
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;
        case 2: /* fill swap hard limit here */
            rc = virCgroupGetMemSwapHardLimit(priv->cgroup, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get swap hard limit"));
                goto cleanup;
            }
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;

        /* coverity[dead_error_begin] */
        default:
            break;
            /* should not hit here */
        }
    }

    if (*nparams > LXC_NB_MEM_PARAM)
        *nparams = LXC_NB_MEM_PARAM;
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}