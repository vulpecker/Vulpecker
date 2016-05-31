

  static void
  CVE_2010_2806_freetype2_2_1_t42_parse_sfnts( T42_Face    face,
                   T42_Loader  loader )
  {
    T42_Parser  parser = &loader->parser;
    FT_Memory   memory = parser->root.memory;
    FT_Byte*    cur;
    FT_Byte*    limit  = parser->root.limit;
    FT_Error    error;
    FT_Int      num_tables = 0;
    FT_ULong    count, ttf_size = 0;

    FT_Long     n, string_size, old_string_size, real_size;
    FT_Byte*    string_buf = NULL;
    FT_Bool     alloc      = 0;

    T42_Load_Status  status;


    /* The format is                                */
    /*                                              */
    /*   /sfnts [ <hexstring> <hexstring> ... ] def */
    /*                                              */
    /* or                                           */
    /*                                              */
    /*   /sfnts [                                   */
    /*      <num_bin_bytes> RD <binary data>        */
    /*      <num_bin_bytes> RD <binary data>        */
    /*      ...                                     */
    /*   ] def                                      */
    /*                                              */
    /* with exactly one space after the `RD' token. */

    T1_Skip_Spaces( parser );

    if ( parser->root.cursor >= limit || *parser->root.cursor++ != '[' )
    {
      FT_ERROR(( "CVE_2010_2806_freetype2_2_1_t42_parse_sfnts: can't find begin of sfnts vector!\n" ));
      error = T42_Err_Invalid_File_Format;
      goto Fail;
    }

    T1_Skip_Spaces( parser );
    status          = BEFORE_START;
    string_size     = 0;
    old_string_size = 0;
    count           = 0;

    while ( parser->root.cursor < limit )
    {
      cur = parser->root.cursor;

      if ( *cur == ']' )
      {
        parser->root.cursor++;
        goto Exit;
      }

      else if ( *cur == '<' )
      {
        T1_Skip_PS_Token( parser );
        if ( parser->root.error )
          goto Exit;

        /* don't include delimiters */
        string_size = (FT_Long)( ( parser->root.cursor - cur - 2 + 1 ) / 2 );
        if ( FT_REALLOC( string_buf, old_string_size, string_size ) )
          goto Fail;

        alloc = 1;

        parser->root.cursor = cur;
        (void)T1_ToBytes( parser, string_buf, string_size, &real_size, 1 );
        old_string_size = string_size;
        string_size = real_size;
      }

      else if ( ft_isdigit( *cur ) )
      {
        string_size = T1_ToInt( parser );

        T1_Skip_PS_Token( parser );             /* `RD' */
        if ( parser->root.error )
          return;

        string_buf = parser->root.cursor + 1;   /* one space after `RD' */

        parser->root.cursor += string_size + 1;
        if ( parser->root.cursor >= limit )
        {
          FT_ERROR(( "CVE_2010_2806_freetype2_2_1_t42_parse_sfnts: too many binary data!\n" ));
          error = T42_Err_Invalid_File_Format;
          goto Fail;
        }
      }

      /* A string can have a trailing zero byte for padding.  Ignore it. */
      if ( string_buf[string_size - 1] == 0 && ( string_size % 2 == 1 ) )
        string_size--;

      for ( n = 0; n < string_size; n++ )
      {
        switch ( status )
        {
        case BEFORE_START:
          /* load offset table, 12 bytes */
          if ( count < 12 )
          {
            face->ttf_data[count++] = string_buf[n];
            continue;
          }
          else
          {
            num_tables = 16 * face->ttf_data[4] + face->ttf_data[5];
            status     = BEFORE_TABLE_DIR;
            ttf_size   = 12 + 16 * num_tables;

            if ( FT_REALLOC( face->ttf_data, 12, ttf_size ) )
              goto Fail;
          }
          /* fall through */

        case BEFORE_TABLE_DIR:
          /* the offset table is read; read the table directory */
          if ( count < ttf_size )
          {
            face->ttf_data[count++] = string_buf[n];
            continue;
          }
          else
          {
            int       i;
            FT_ULong  len;


            for ( i = 0; i < num_tables; i++ )
            {
              FT_Byte*  p = face->ttf_data + 12 + 16 * i + 12;


              len = FT_PEEK_ULONG( p );

              /* Pad to a 4-byte boundary length */
              ttf_size += ( len + 3 ) & ~3;
            }

            status         = OTHER_TABLES;
            face->ttf_size = ttf_size;

            /* there are no more than 256 tables, so no size check here */
            if ( FT_REALLOC( face->ttf_data, 12 + 16 * num_tables,
                             ttf_size + 1 ) )
              goto Fail;
          }
          /* fall through */

        case OTHER_TABLES:
          /* all other tables are just copied */
          if ( count >= ttf_size )
          {
            FT_ERROR(( "CVE_2010_2806_freetype2_2_1_t42_parse_sfnts: too many binary data!\n" ));
            error = T42_Err_Invalid_File_Format;
            goto Fail;
          }
          face->ttf_data[count++] = string_buf[n];
        }
      }

      T1_Skip_Spaces( parser );
    }

    /* if control reaches this point, the format was not valid */
    error = T42_Err_Invalid_File_Format;

  Fail:
    parser->root.error = error;

  Exit:
    if ( alloc )
      FT_FREE( string_buf );
  }