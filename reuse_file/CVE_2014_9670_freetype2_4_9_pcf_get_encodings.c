

  static FT_Error
  CVE_2014_9670_freetype2_4_9_pcf_get_encodings( FT_Stream  stream,
                     PCF_Face   face )
  {
    FT_Error      error  = PCF_Err_Ok;
    FT_Memory     memory = FT_FACE(face)->memory;
    FT_ULong      format, size;
    int           firstCol, lastCol;
    int           firstRow, lastRow;
    int           nencoding, encodingOffset;
    int           i, j;
    PCF_Encoding  tmpEncoding = NULL, encoding = 0;


    error = pcf_seek_to_table_type( stream,
                                    face->toc.tables,
                                    face->toc.count,
                                    PCF_BDF_ENCODINGS,
                                    &format,
                                    &size );
    if ( error )
      return error;

    error = FT_Stream_EnterFrame( stream, 14 );
    if ( error )
      return error;

    format = FT_GET_ULONG_LE();

    if ( PCF_BYTE_ORDER( format ) == MSBFirst )
    {
      firstCol          = FT_GET_SHORT();
      lastCol           = FT_GET_SHORT();
      firstRow          = FT_GET_SHORT();
      lastRow           = FT_GET_SHORT();
      face->defaultChar = FT_GET_SHORT();
    }
    else
    {
      firstCol          = FT_GET_SHORT_LE();
      lastCol           = FT_GET_SHORT_LE();
      firstRow          = FT_GET_SHORT_LE();
      lastRow           = FT_GET_SHORT_LE();
      face->defaultChar = FT_GET_SHORT_LE();
    }

    FT_Stream_ExitFrame( stream );

    if ( !PCF_FORMAT_MATCH( format, PCF_DEFAULT_FORMAT ) )
      return PCF_Err_Invalid_File_Format;

    FT_TRACE4(( "pdf_get_encodings:\n" ));

    FT_TRACE4(( "  firstCol %d, lastCol %d, firstRow %d, lastRow %d\n",
                firstCol, lastCol, firstRow, lastRow ));

    nencoding = ( lastCol - firstCol + 1 ) * ( lastRow - firstRow + 1 );

    if ( FT_NEW_ARRAY( tmpEncoding, nencoding ) )
      return PCF_Err_Out_Of_Memory;

    error = FT_Stream_EnterFrame( stream, 2 * nencoding );
    if ( error )
      goto Bail;

    for ( i = 0, j = 0 ; i < nencoding; i++ )
    {
      if ( PCF_BYTE_ORDER( format ) == MSBFirst )
        encodingOffset = FT_GET_SHORT();
      else
        encodingOffset = FT_GET_SHORT_LE();

      if ( encodingOffset != -1 )
      {
        tmpEncoding[j].enc = ( ( ( i / ( lastCol - firstCol + 1 ) ) +
                                 firstRow ) * 256 ) +
                               ( ( i % ( lastCol - firstCol + 1 ) ) +
                                 firstCol );

        tmpEncoding[j].glyph = (FT_Short)encodingOffset;

        FT_TRACE5(( "  code %d (0x%04X): idx %d\n",
                    tmpEncoding[j].enc, tmpEncoding[j].enc,
                    tmpEncoding[j].glyph ));

        j++;
      }
    }
    FT_Stream_ExitFrame( stream );

    if ( FT_NEW_ARRAY( encoding, j ) )
      goto Bail;

    for ( i = 0; i < j; i++ )
    {
      encoding[i].enc   = tmpEncoding[i].enc;
      encoding[i].glyph = tmpEncoding[i].glyph;
    }

    face->nencodings = j;
    face->encodings  = encoding;
    FT_FREE( tmpEncoding );

    return error;

  Bail:
    FT_FREE( encoding );
    FT_FREE( tmpEncoding );
    return error;
  }