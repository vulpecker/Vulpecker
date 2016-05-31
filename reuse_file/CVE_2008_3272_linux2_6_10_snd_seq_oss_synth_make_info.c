int
CVE_2008_3272_linux2_6_10_snd_seq_oss_synth_make_info(seq_oss_devinfo_t *dp, int dev, struct synth_info *inf)
{
	seq_oss_synth_t *rec;

	if (dp->synths[dev].is_midi) {
		struct midi_info minf;
		snd_seq_oss_midi_make_info(dp, dp->synths[dev].midi_mapped, &minf);
		inf->synth_type = SYNTH_TYPE_MIDI;
		inf->synth_subtype = 0;
		inf->nr_voices = 16;
		inf->device = dev;
		strlcpy(inf->name, minf.name, sizeof(inf->name));
	} else {
		if ((rec = get_synthdev(dp, dev)) == NULL)
			return -ENXIO;
		inf->synth_type = rec->synth_type;
		inf->synth_subtype = rec->synth_subtype;
		inf->nr_voices = rec->nr_voices;
		inf->device = dev;
		strlcpy(inf->name, rec->name, sizeof(inf->name));
		snd_use_lock_free(&rec->use_lock);
	}
	return 0;
}