static void CVE_2010_3907_vlc_media_player0_9_5_Close( vlc_object_t *p_this )
{
    demux_t *p_demux = (demux_t*)p_this;
    demux_sys_t *p_sys = p_demux->p_sys;
    int i;

    for( i = 0; i < p_sys->i_track; i++ )
    {
        real_track_t *tk = p_sys->track[i];
        int j = tk->i_subpackets;

        if( tk->p_frame ) block_Release( tk->p_frame );
        es_format_Clean( &tk->fmt );

        while(  j-- )
        {
            if( tk->p_subpackets[ j ] )
                block_Release( tk->p_subpackets[ j ] );
        }
        if( tk->i_subpackets )
        {
            free( tk->p_subpackets );
            free( tk->p_subpackets_timecode );
        }

        free( tk );
    }

    free( p_sys->psz_title );
    free( p_sys->psz_artist );
    free( p_sys->psz_copyright );
    free( p_sys->psz_description );
    free( p_sys->p_index );

    if( p_sys->i_track > 0 ) free( p_sys->track );
    free( p_sys );
}