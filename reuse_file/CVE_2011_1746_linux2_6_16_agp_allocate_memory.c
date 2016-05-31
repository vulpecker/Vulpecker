struct agp_memory *CVE_2011_1746_linux2_6_16_agp_allocate_memory(struct agp_bridge_data *bridge,
					size_t page_count, u32 type)
{
	int scratch_pages;
	struct agp_memory *new;
	size_t i;

	if (!bridge)
		return NULL;

	if ((atomic_read(&bridge->current_memory_agp) + page_count) > bridge->max_memory_agp)
		return NULL;

	if (type != 0) {
		new = bridge->driver->alloc_by_type(page_count, type);
		if (new)
			new->bridge = bridge;
		return new;
	}

	scratch_pages = (page_count + ENTRIES_PER_PAGE - 1) / ENTRIES_PER_PAGE;

	new = agp_create_memory(scratch_pages);

	if (new == NULL)
		return NULL;

	for (i = 0; i < page_count; i++) {
		void *addr = bridge->driver->agp_alloc_page(bridge);

		if (addr == NULL) {
			agp_free_memory(new);
			return NULL;
		}
		new->memory[i] = virt_to_gart(addr);
		new->page_count++;
	}
	new->bridge = bridge;

	flush_agp_mappings();

	return new;
}