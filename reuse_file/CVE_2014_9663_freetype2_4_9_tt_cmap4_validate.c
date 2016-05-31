  CVE_2014_9663_freetype2_4_9_tt_cmap4_validate( FT_Byte*      table,
                     FT_Validator  valid )
  {
    FT_Byte*  p      = table + 2;               /* skip format */
    FT_UInt   length = TT_NEXT_USHORT( p );
    FT_Byte   *ends, *starts, *offsets, *deltas, *glyph_ids;
    FT_UInt   num_segs;
    FT_Error  error = SFNT_Err_Ok;


    if ( length < 16 )
      FT_INVALID_TOO_SHORT;

    /* in certain fonts, the `length' field is invalid and goes */
    /* out of bound.  We try to correct this here...            */
    if ( table + length > valid->limit )
    {
      if ( valid->level >= FT_VALIDATE_TIGHT )
        FT_INVALID_TOO_SHORT;

      length = (FT_UInt)( valid->limit - table );
    }

    p        = table + 6;
    num_segs = TT_NEXT_USHORT( p );   /* read segCountX2 */

    if ( valid->level >= FT_VALIDATE_PARANOID )
    {
      /* check that we have an even value here */
      if ( num_segs & 1 )
        FT_INVALID_DATA;
    }

    num_segs /= 2;

    if ( length < 16 + num_segs * 2 * 4 )
      FT_INVALID_TOO_SHORT;

    /* check the search parameters - even though we never use them */
    /*                                                             */
    if ( valid->level >= FT_VALIDATE_PARANOID )
    {
      /* check the values of `searchRange', `entrySelector', `rangeShift' */
      FT_UInt  search_range   = TT_NEXT_USHORT( p );
      FT_UInt  entry_selector = TT_NEXT_USHORT( p );
      FT_UInt  range_shift    = TT_NEXT_USHORT( p );


      if ( ( search_range | range_shift ) & 1 )  /* must be even values */
        FT_INVALID_DATA;

      search_range /= 2;
      range_shift  /= 2;

      /* `search range' is the greatest power of 2 that is <= num_segs */

      if ( search_range                > num_segs                 ||
           search_range * 2            < num_segs                 ||
           search_range + range_shift != num_segs                 ||
           search_range               != ( 1U << entry_selector ) )
        FT_INVALID_DATA;
    }

    ends      = table   + 14;
    starts    = table   + 16 + num_segs * 2;
    deltas    = starts  + num_segs * 2;
    offsets   = deltas  + num_segs * 2;
    glyph_ids = offsets + num_segs * 2;

    /* check last segment; its end count value must be 0xFFFF */
    if ( valid->level >= FT_VALIDATE_PARANOID )
    {
      p = ends + ( num_segs - 1 ) * 2;
      if ( TT_PEEK_USHORT( p ) != 0xFFFFU )
        FT_INVALID_DATA;
    }

    {
      FT_UInt   start, end, offset, n;
      FT_UInt   last_start = 0, last_end = 0;
      FT_Int    delta;
      FT_Byte*  p_start   = starts;
      FT_Byte*  p_end     = ends;
      FT_Byte*  p_delta   = deltas;
      FT_Byte*  p_offset  = offsets;


      for ( n = 0; n < num_segs; n++ )
      {
        p      = p_offset;
        start  = TT_NEXT_USHORT( p_start );
        end    = TT_NEXT_USHORT( p_end );
        delta  = TT_NEXT_SHORT( p_delta );
        offset = TT_NEXT_USHORT( p_offset );

        if ( start > end )
          FT_INVALID_DATA;

        /* this test should be performed at default validation level; */
        /* unfortunately, some popular Asian fonts have overlapping   */
        /* ranges in their charmaps                                   */
        /*                                                            */
        if ( start <= last_end && n > 0 )
        {
          if ( valid->level >= FT_VALIDATE_TIGHT )
            FT_INVALID_DATA;
          else
          {
            /* allow overlapping segments, provided their start points */
            /* and end points, respectively, are in ascending order    */
            /*                                                         */
            if ( last_start > start || last_end > end )
              error |= TT_CMAP_FLAG_UNSORTED;
            else
              error |= TT_CMAP_FLAG_OVERLAPPING;
          }
        }

        if ( offset && offset != 0xFFFFU )
        {
          p += offset;  /* start of glyph ID array */

          /* check that we point within the glyph IDs table only */
          if ( valid->level >= FT_VALIDATE_TIGHT )
          {
            if ( p < glyph_ids                                ||
                 p + ( end - start + 1 ) * 2 > table + length )
              FT_INVALID_DATA;
          }
          /* Some fonts handle the last segment incorrectly.  In */
          /* theory, 0xFFFF might point to an ordinary glyph --  */
          /* a cmap 4 is versatile and could be used for any     */
          /* encoding, not only Unicode.  However, reality shows */
          /* that far too many fonts are sloppy and incorrectly  */
          /* set all fields but `start' and `end' for the last   */
          /* segment if it contains only a single character.     */
          /*                                                     */
          /* We thus omit the test here, delaying it to the      */
          /* routines which actually access the cmap.            */
          else if ( n != num_segs - 1                       ||
                    !( start == 0xFFFFU && end == 0xFFFFU ) )
          {
            if ( p < glyph_ids                              ||
                 p + ( end - start + 1 ) * 2 > valid->limit )
              FT_INVALID_DATA;
          }

          /* check glyph indices within the segment range */
          if ( valid->level >= FT_VALIDATE_TIGHT )
          {
            FT_UInt  i, idx;


            for ( i = start; i < end; i++ )
            {
              idx = FT_NEXT_USHORT( p );
              if ( idx != 0 )
              {
                idx = (FT_UInt)( idx + delta ) & 0xFFFFU;

                if ( idx >= TT_VALID_GLYPH_COUNT( valid ) )
                  FT_INVALID_GLYPH_ID;
              }
            }
          }
        }
        else if ( offset == 0xFFFFU )
        {
          /* some fonts (erroneously?) use a range offset of 0xFFFF */
          /* to mean missing glyph in cmap table                    */
          /*                                                        */
          if ( valid->level >= FT_VALIDATE_PARANOID    ||
               n != num_segs - 1                       ||
               !( start == 0xFFFFU && end == 0xFFFFU ) )
            FT_INVALID_DATA;
        }

        last_start = start;
        last_end   = end;
      }
    }

    return error;
  }