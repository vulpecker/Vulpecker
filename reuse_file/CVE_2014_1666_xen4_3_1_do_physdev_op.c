
ret_t CVE_2014_1666_xen4_3_1_do_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int irq;
    ret_t ret;
    struct vcpu *v = current;

    switch ( cmd )
    {
    case PHYSDEVOP_eoi: {
        struct physdev_eoi eoi;
        struct pirq *pirq;

        ret = -EFAULT;
        if ( copy_from_guest(&eoi, arg, 1) != 0 )
            break;
        ret = -EINVAL;
        if ( eoi.irq >= v->domain->nr_pirqs )
            break;
        spin_lock(&v->domain->event_lock);
        pirq = pirq_info(v->domain, eoi.irq);
        if ( !pirq ) {
            spin_unlock(&v->domain->event_lock);
            break;
        }
        if ( !is_hvm_domain(v->domain) &&
             v->domain->arch.pv_domain.auto_unmask )
            evtchn_unmask(pirq->evtchn);
        if ( !is_hvm_domain(v->domain) ||
             domain_pirq_to_irq(v->domain, eoi.irq) > 0 )
            pirq_guest_eoi(pirq);
        if ( is_hvm_domain(v->domain) &&
                domain_pirq_to_emuirq(v->domain, eoi.irq) > 0 )
        {
            struct hvm_irq *hvm_irq = &v->domain->arch.hvm_domain.irq;
            int gsi = domain_pirq_to_emuirq(v->domain, eoi.irq);

            /* if this is a level irq and count > 0, send another
             * notification */ 
            if ( gsi >= NR_ISAIRQS /* ISA irqs are edge triggered */
                    && hvm_irq->gsi_assert_count[gsi] )
                send_guest_pirq(v->domain, pirq);
        }
        spin_unlock(&v->domain->event_lock);
        ret = 0;
        break;
    }

    case PHYSDEVOP_pirq_eoi_gmfn_v2:
    case PHYSDEVOP_pirq_eoi_gmfn_v1: {
        struct physdev_pirq_eoi_gmfn info;
        unsigned long mfn;
        struct page_info *page;

        ret = -EFAULT;
        if ( copy_from_guest(&info, arg, 1) != 0 )
            break;

        ret = -EINVAL;
        page = get_page_from_gfn(current->domain, info.gmfn, NULL, P2M_ALLOC);
        if ( !page )
            break;
        if ( !get_page_type(page, PGT_writable_page) )
        {
            put_page(page);
            break;
        }
        mfn = page_to_mfn(page);

        if ( cmpxchg(&v->domain->arch.pv_domain.pirq_eoi_map_mfn,
                     0, mfn) != 0 )
        {
            put_page_and_type(mfn_to_page(mfn));
            ret = -EBUSY;
            break;
        }

        v->domain->arch.pv_domain.pirq_eoi_map = map_domain_page_global(mfn);
        if ( v->domain->arch.pv_domain.pirq_eoi_map == NULL )
        {
            v->domain->arch.pv_domain.pirq_eoi_map_mfn = 0;
            put_page_and_type(mfn_to_page(mfn));
            ret = -ENOSPC;
            break;
        }
        if ( cmd == PHYSDEVOP_pirq_eoi_gmfn_v1 )
            v->domain->arch.pv_domain.auto_unmask = 1;

        ret = 0;
        break;
    }

    /* Legacy since 0x00030202. */
    case PHYSDEVOP_IRQ_UNMASK_NOTIFY: {
        ret = pirq_guest_unmask(v->domain);
        break;
    }

    case PHYSDEVOP_irq_status_query: {
        struct physdev_irq_status_query irq_status_query;
        ret = -EFAULT;
        if ( copy_from_guest(&irq_status_query, arg, 1) != 0 )
            break;
        irq = irq_status_query.irq;
        ret = -EINVAL;
        if ( (irq < 0) || (irq >= v->domain->nr_pirqs) )
            break;
        irq_status_query.flags = 0;
        if ( is_hvm_domain(v->domain) &&
             domain_pirq_to_irq(v->domain, irq) <= 0 &&
             domain_pirq_to_emuirq(v->domain, irq) == IRQ_UNBOUND )
        {
            ret = -EINVAL;
            break;
        }

        /*
         * Even edge-triggered or message-based IRQs can need masking from
         * time to time. If teh guest is not dynamically checking for this
         * via the new pirq_eoi_map mechanism, it must conservatively always
         * execute the EOI hypercall. In practice, this only really makes a
         * difference for maskable MSI sources, and if those are supported
         * then dom0 is probably modern anyway.
         */
        irq_status_query.flags |= XENIRQSTAT_needs_eoi;
        if ( pirq_shared(v->domain, irq) )
            irq_status_query.flags |= XENIRQSTAT_shared;
        ret = __copy_to_guest(arg, &irq_status_query, 1) ? -EFAULT : 0;
        break;
    }

    case PHYSDEVOP_map_pirq: {
        physdev_map_pirq_t map;
        struct msi_info msi;

        ret = -EFAULT;
        if ( copy_from_guest(&map, arg, 1) != 0 )
            break;

        if ( map.type == MAP_PIRQ_TYPE_MSI_SEG )
        {
            map.type = MAP_PIRQ_TYPE_MSI;
            msi.seg = map.bus >> 16;
        }
        else
        {
            msi.seg = 0;
        }
        msi.bus = map.bus;
        msi.devfn = map.devfn;
        msi.entry_nr = map.entry_nr;
        msi.table_base = map.table_base;
        ret = physdev_map_pirq(map.domid, map.type, &map.index, &map.pirq,
                               &msi);

        if ( __copy_to_guest(arg, &map, 1) )
            ret = -EFAULT;
        break;
    }

    case PHYSDEVOP_unmap_pirq: {
        struct physdev_unmap_pirq unmap;

        ret = -EFAULT;
        if ( copy_from_guest(&unmap, arg, 1) != 0 )
            break;

        ret = physdev_unmap_pirq(unmap.domid, unmap.pirq);
        break;
    }

    case PHYSDEVOP_apic_read: {
        struct physdev_apic apic;
        ret = -EFAULT;
        if ( copy_from_guest(&apic, arg, 1) != 0 )
            break;
        ret = xsm_apic(XSM_PRIV, v->domain, cmd);
        if ( ret )
            break;
        ret = ioapic_guest_read(apic.apic_physbase, apic.reg, &apic.value);
        if ( __copy_to_guest(arg, &apic, 1) )
            ret = -EFAULT;
        break;
    }

    case PHYSDEVOP_apic_write: {
        struct physdev_apic apic;
        ret = -EFAULT;
        if ( copy_from_guest(&apic, arg, 1) != 0 )
            break;
        ret = xsm_apic(XSM_PRIV, v->domain, cmd);
        if ( ret )
            break;
        ret = ioapic_guest_write(apic.apic_physbase, apic.reg, apic.value);
        break;
    }

    case PHYSDEVOP_alloc_irq_vector: {
        struct physdev_irq irq_op;

        ret = -EFAULT;
        if ( copy_from_guest(&irq_op, arg, 1) != 0 )
            break;

        /* Use the APIC check since this dummy hypercall should still only
         * be called by the domain with access to program the ioapic */
        ret = xsm_apic(XSM_PRIV, v->domain, cmd);
        if ( ret )
            break;

        /* Vector is only used by hypervisor, and dom0 shouldn't
           touch it in its world, return irq_op.irq as the vecotr,
           and make this hypercall dummy, and also defer the vector 
           allocation when dom0 tries to programe ioapic entry. */
        irq_op.vector = irq_op.irq;
        ret = 0;
        
        if ( __copy_to_guest(arg, &irq_op, 1) )
            ret = -EFAULT;
        break;
    }

    case PHYSDEVOP_set_iopl: {
        struct physdev_set_iopl set_iopl;
        ret = -EFAULT;
        if ( copy_from_guest(&set_iopl, arg, 1) != 0 )
            break;
        ret = -EINVAL;
        if ( set_iopl.iopl > 3 )
            break;
        ret = 0;
        v->arch.pv_vcpu.iopl = set_iopl.iopl;
        break;
    }

    case PHYSDEVOP_set_iobitmap: {
        struct physdev_set_iobitmap set_iobitmap;
        ret = -EFAULT;
        if ( copy_from_guest(&set_iobitmap, arg, 1) != 0 )
            break;
        ret = -EINVAL;
        if ( !guest_handle_okay(set_iobitmap.bitmap, IOBMP_BYTES) ||
             (set_iobitmap.nr_ports > 65536) )
            break;
        ret = 0;
#ifndef COMPAT
        v->arch.pv_vcpu.iobmp = set_iobitmap.bitmap;
#else
        guest_from_compat_handle(v->arch.pv_vcpu.iobmp, set_iobitmap.bitmap);
#endif
        v->arch.pv_vcpu.iobmp_limit = set_iobitmap.nr_ports;
        break;
    }

    case PHYSDEVOP_manage_pci_add: {
        struct physdev_manage_pci manage_pci;
        ret = -EFAULT;
        if ( copy_from_guest(&manage_pci, arg, 1) != 0 )
            break;

        ret = pci_add_device(0, manage_pci.bus, manage_pci.devfn, NULL);
        break;
    }

    case PHYSDEVOP_manage_pci_remove: {
        struct physdev_manage_pci manage_pci;
        ret = -EFAULT;
        if ( copy_from_guest(&manage_pci, arg, 1) != 0 )
            break;

        ret = pci_remove_device(0, manage_pci.bus, manage_pci.devfn);
        break;
    }

    case PHYSDEVOP_manage_pci_add_ext: {
        struct physdev_manage_pci_ext manage_pci_ext;
        struct pci_dev_info pdev_info;

        ret = -EFAULT;
        if ( copy_from_guest(&manage_pci_ext, arg, 1) != 0 )
            break;

        ret = -EINVAL;
        if ( (manage_pci_ext.is_extfn > 1) || (manage_pci_ext.is_virtfn > 1) )
            break;

        pdev_info.is_extfn = manage_pci_ext.is_extfn;
        pdev_info.is_virtfn = manage_pci_ext.is_virtfn;
        pdev_info.physfn.bus = manage_pci_ext.physfn.bus;
        pdev_info.physfn.devfn = manage_pci_ext.physfn.devfn;
        ret = pci_add_device(0, manage_pci_ext.bus,
                             manage_pci_ext.devfn,
                             &pdev_info);
        break;
    }

    case PHYSDEVOP_pci_device_add: {
        struct physdev_pci_device_add add;
        struct pci_dev_info pdev_info;

        ret = -EFAULT;
        if ( copy_from_guest(&add, arg, 1) != 0 )
            break;

        pdev_info.is_extfn = !!(add.flags & XEN_PCI_DEV_EXTFN);
        if ( add.flags & XEN_PCI_DEV_VIRTFN )
        {
            pdev_info.is_virtfn = 1;
            pdev_info.physfn.bus = add.physfn.bus;
            pdev_info.physfn.devfn = add.physfn.devfn;
        }
        else
            pdev_info.is_virtfn = 0;
        ret = pci_add_device(add.seg, add.bus, add.devfn, &pdev_info);
        break;
    }

    case PHYSDEVOP_pci_device_remove: {
        struct physdev_pci_device dev;

        ret = -EFAULT;
        if ( copy_from_guest(&dev, arg, 1) != 0 )
            break;

        ret = pci_remove_device(dev.seg, dev.bus, dev.devfn);
        break;
    }

    case PHYSDEVOP_prepare_msix:
    case PHYSDEVOP_release_msix: {
        struct physdev_pci_device dev;

        if ( copy_from_guest(&dev, arg, 1) )
            ret = -EFAULT;
        else
            ret = pci_prepare_msix(dev.seg, dev.bus, dev.devfn,
                                   cmd != PHYSDEVOP_prepare_msix);
        break;
    }

    case PHYSDEVOP_pci_mmcfg_reserved: {
        struct physdev_pci_mmcfg_reserved info;

        ret = xsm_resource_setup_misc(XSM_PRIV);
        if ( ret )
            break;

        ret = -EFAULT;
        if ( copy_from_guest(&info, arg, 1) )
            break;

        ret = pci_mmcfg_reserved(info.address, info.segment,
                                 info.start_bus, info.end_bus, info.flags);
        break;
    }

    case PHYSDEVOP_restore_msi: {
        struct physdev_restore_msi restore_msi;
        struct pci_dev *pdev;

        ret = -EFAULT;
        if ( copy_from_guest(&restore_msi, arg, 1) != 0 )
            break;

        spin_lock(&pcidevs_lock);
        pdev = pci_get_pdev(0, restore_msi.bus, restore_msi.devfn);
        ret = pdev ? pci_restore_msi_state(pdev) : -ENODEV;
        spin_unlock(&pcidevs_lock);
        break;
    }

    case PHYSDEVOP_restore_msi_ext: {
        struct physdev_pci_device dev;
        struct pci_dev *pdev;

        ret = -EFAULT;
        if ( copy_from_guest(&dev, arg, 1) != 0 )
            break;

        spin_lock(&pcidevs_lock);
        pdev = pci_get_pdev(dev.seg, dev.bus, dev.devfn);
        ret = pdev ? pci_restore_msi_state(pdev) : -ENODEV;
        spin_unlock(&pcidevs_lock);
        break;
    }

    case PHYSDEVOP_setup_gsi: {
        struct physdev_setup_gsi setup_gsi;

        ret = -EFAULT;
        if ( copy_from_guest(&setup_gsi, arg, 1) != 0 )
            break;
        
        ret = -EINVAL;
        if ( setup_gsi.gsi < 0 || setup_gsi.gsi >= nr_irqs_gsi )
            break;

        ret = xsm_resource_setup_gsi(XSM_PRIV, setup_gsi.gsi);
        if ( ret )
            break;

        ret = mp_register_gsi(setup_gsi.gsi, setup_gsi.triggering,
                              setup_gsi.polarity);
        break; 
    }
    case PHYSDEVOP_get_free_pirq: {
        struct physdev_get_free_pirq out;
        struct domain *d = v->domain;

        ret = -EFAULT;
        if ( copy_from_guest(&out, arg, 1) != 0 )
            break;

        spin_lock(&d->event_lock);

        ret = get_free_pirq(d, out.type);
        if ( ret >= 0 )
        {
            struct pirq *info = pirq_get_info(d, ret);

            if ( info )
                info->arch.irq = PIRQ_ALLOCATED;
            else
                ret = -ENOMEM;
        }

        spin_unlock(&d->event_lock);

        if ( ret >= 0 )
        {
            out.pirq = ret;
            ret = __copy_to_guest(arg, &out, 1) ? -EFAULT : 0;
        }

        break;
    }

    case PHYSDEVOP_dbgp_op: {
        struct physdev_dbgp_op op;

        if ( !is_hardware_domain(v->domain) )
            ret = -EPERM;
        else if ( copy_from_guest(&op, arg, 1) )
            ret = -EFAULT;
        else
            ret = dbgp_op(&op);
        break;
    }

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}