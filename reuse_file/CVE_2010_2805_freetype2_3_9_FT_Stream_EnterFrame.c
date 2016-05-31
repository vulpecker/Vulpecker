  CVE_2010_2805_freetype2_3_9_FT_Stream_EnterFrame( FT_Stream  stream,
                        FT_ULong   count )
  {
    FT_Error  error = FT_Err_Ok;
    FT_ULong  read_bytes;


    /* check for nested frame access */
    FT_ASSERT( stream && stream->cursor == 0 );

    if ( stream->read )
    {
      /* allocate the frame in memory */
      FT_Memory  memory = stream->memory;

#ifdef FT_DEBUG_MEMORY
      /* assume _ft_debug_file and _ft_debug_lineno are already set */
      stream->base = (unsigned char*)ft_mem_qalloc( memory, count, &error );
      if ( error )
        goto Exit;
#else
      if ( FT_QALLOC( stream->base, count ) )
        goto Exit;
#endif
      /* read it */
      read_bytes = stream->read( stream, stream->pos,
                                 stream->base, count );
      if ( read_bytes < count )
      {
        FT_ERROR(( "CVE_2010_2805_freetype2_3_9_FT_Stream_EnterFrame:" ));
        FT_ERROR(( " invalid read; expected %lu bytes, got %lu\n",
                   count, read_bytes ));

        FT_FREE( stream->base );
        error = FT_Err_Invalid_Stream_Operation;
      }
      stream->cursor = stream->base;
      stream->limit  = stream->cursor + count;
      stream->pos   += read_bytes;
    }
    else
    {
      /* check current and new position */
      if ( stream->pos >= stream->size        ||
           stream->pos + count > stream->size )
      {
        FT_ERROR(( "CVE_2010_2805_freetype2_3_9_FT_Stream_EnterFrame:" ));
        FT_ERROR(( " invalid i/o; pos = 0x%lx, count = %lu, size = 0x%lx\n",
                   stream->pos, count, stream->size ));

        error = FT_Err_Invalid_Stream_Operation;
        goto Exit;
      }

      /* set cursor */
      stream->cursor = stream->base + stream->pos;
      stream->limit  = stream->cursor + count;
      stream->pos   += count;
    }

  Exit:
    return error;
  }