
static int tiff_decode_tag(TiffContext *s)
{
    unsigned tag, type, count, off, value = 0;
    int i, j, k, pos, start;
    int ret;
    uint32_t *pal;
    double *dp;

    tag   = tget_short(&s->gb, s->le);
    type  = tget_short(&s->gb, s->le);
    count = tget_long(&s->gb, s->le);
    off   = tget_long(&s->gb, s->le);
    start = bytestream2_tell(&s->gb);

    if (type == 0 || type >= FF_ARRAY_ELEMS(type_sizes)) {
        av_log(s->avctx, AV_LOG_DEBUG, "Unknown tiff type (%u) encountered\n",
               type);
        return 0;
    }

    if (count == 1) {
        switch (type) {
        case TIFF_BYTE:
        case TIFF_SHORT:
            bytestream2_seek(&s->gb, -4, SEEK_CUR);
            value = tget(&s->gb, type, s->le);
            break;
        case TIFF_LONG:
            value = off;
            break;
        case TIFF_STRING:
            if (count <= 4) {
                bytestream2_seek(&s->gb, -4, SEEK_CUR);
                break;
            }
        default:
            value = UINT_MAX;
            bytestream2_seek(&s->gb, off, SEEK_SET);
        }
    } else {
        if (count <= 4 && type_sizes[type] * count <= 4) {
            bytestream2_seek(&s->gb, -4, SEEK_CUR);
        } else {
            bytestream2_seek(&s->gb, off, SEEK_SET);
        }
    }

    switch (tag) {
    case TIFF_WIDTH:
        s->width = value;
        break;
    case TIFF_HEIGHT:
        s->height = value;
        break;
    case TIFF_BPP:
        s->bppcount = count;
        if (count > 4) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "This format is not supported (bpp=%d, %d components)\n",
                   s->bpp, count);
            return -1;
        }
        if (count == 1)
            s->bpp = value;
        else {
            switch (type) {
            case TIFF_BYTE:
                s->bpp = (off & 0xFF) + ((off >> 8) & 0xFF) +
                         ((off >> 16) & 0xFF) + ((off >> 24) & 0xFF);
                break;
            case TIFF_SHORT:
            case TIFF_LONG:
                s->bpp = 0;
                if (bytestream2_get_bytes_left(&s->gb) < type_sizes[type] * count)
                    return -1;
                for (i = 0; i < count; i++)
                    s->bpp += tget(&s->gb, type, s->le);
                break;
            default:
                s->bpp = -1;
            }
        }
        break;
    case TIFF_SAMPLES_PER_PIXEL:
        if (count != 1) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "Samples per pixel requires a single value, many provided\n");
            return AVERROR_INVALIDDATA;
        }
        if (s->bppcount == 1)
            s->bpp *= value;
        s->bppcount = value;
        break;
    case TIFF_COMPR:
        s->compr = value;
        s->predictor = 0;
        switch (s->compr) {
        case TIFF_RAW:
        case TIFF_PACKBITS:
        case TIFF_LZW:
        case TIFF_CCITT_RLE:
            break;
        case TIFF_G3:
        case TIFF_G4:
            s->fax_opts = 0;
            break;
        case TIFF_DEFLATE:
        case TIFF_ADOBE_DEFLATE:
#if CONFIG_ZLIB
            break;
#else
            av_log(s->avctx, AV_LOG_ERROR, "Deflate: ZLib not compiled in\n");
            return -1;
#endif
        case TIFF_JPEG:
        case TIFF_NEWJPEG:
            av_log(s->avctx, AV_LOG_ERROR,
                   "JPEG compression is not supported\n");
            return -1;
        default:
            av_log(s->avctx, AV_LOG_ERROR, "Unknown compression method %i\n",
                   s->compr);
            return -1;
        }
        break;
    case TIFF_ROWSPERSTRIP:
        if (type == TIFF_LONG && value == UINT_MAX)
            value = s->height;
        if (value < 1) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "Incorrect value of rows per strip\n");
            return -1;
        }
        s->rps = value;
        break;
    case TIFF_STRIP_OFFS:
        if (count == 1) {
            s->strippos = 0;
            s->stripoff = value;
        } else
            s->strippos = off;
        s->strips = count;
        if (s->strips == 1)
            s->rps = s->height;
        s->sot = type;
        if (s->strippos > bytestream2_size(&s->gb)) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "Tag referencing position outside the image\n");
            return -1;
        }
        break;
    case TIFF_STRIP_SIZE:
        if (count == 1) {
            s->stripsizesoff = 0;
            s->stripsize = value;
            s->strips = 1;
        } else {
            s->stripsizesoff = off;
        }
        s->strips = count;
        s->sstype = type;
        if (s->stripsizesoff > bytestream2_size(&s->gb)) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "Tag referencing position outside the image\n");
            return -1;
        }
        break;
    case TIFF_TILE_BYTE_COUNTS:
    case TIFF_TILE_LENGTH:
    case TIFF_TILE_OFFSETS:
    case TIFF_TILE_WIDTH:
        av_log(s->avctx, AV_LOG_ERROR, "Tiled images are not supported\n");
        return AVERROR_PATCHWELCOME;
        break;
    case TIFF_PREDICTOR:
        s->predictor = value;
        break;
    case TIFF_INVERT:
        switch (value) {
        case 0:
            s->invert = 1;
            break;
        case 1:
            s->invert = 0;
            break;
        case 2:
        case 3:
            break;
        default:
            av_log(s->avctx, AV_LOG_ERROR, "Color mode %d is not supported\n",
                   value);
            return -1;
        }
        break;
    case TIFF_FILL_ORDER:
        if (value < 1 || value > 2) {
            av_log(s->avctx, AV_LOG_ERROR,
                   "Unknown FillOrder value %d, trying default one\n", value);
            value = 1;
        }
        s->fill_order = value - 1;
        break;
    case TIFF_PAL:
        pal = (uint32_t *) s->palette;
        off = type_sizes[type];
        if (count / 3 > 256 || bytestream2_get_bytes_left(&s->gb) < count / 3 * off * 3)
            return -1;
        off = (type_sizes[type] - 1) << 3;
        for (k = 2; k >= 0; k--) {
            for (i = 0; i < count / 3; i++) {
                if (k == 2)
                    pal[i] = 0xFFU << 24;
                j =  (tget(&s->gb, type, s->le) >> off) << (k * 8);
                pal[i] |= j;
            }
        }
        s->palette_is_set = 1;
        break;
    case TIFF_PLANAR:
        if (value == 2) {
            av_log(s->avctx, AV_LOG_ERROR, "Planar format is not supported\n");
            return -1;
        }
        break;
    case TIFF_T4OPTIONS:
        if (s->compr == TIFF_G3)
            s->fax_opts = value;
        break;
    case TIFF_T6OPTIONS:
        if (s->compr == TIFF_G4)
            s->fax_opts = value;
        break;
#define ADD_METADATA(count, name, sep)\
    if ((ret = add_metadata(count, type, name, sep, s)) < 0) {\
        av_log(s->avctx, AV_LOG_ERROR, "Error allocating temporary buffer\n");\
        return ret;\
    }
    case TIFF_MODEL_PIXEL_SCALE:
        ADD_METADATA(count, "ModelPixelScaleTag", NULL);
        break;
    case TIFF_MODEL_TRANSFORMATION:
        ADD_METADATA(count, "ModelTransformationTag", NULL);
        break;
    case TIFF_MODEL_TIEPOINT:
        ADD_METADATA(count, "ModelTiepointTag", NULL);
        break;
    case TIFF_GEO_KEY_DIRECTORY:
        ADD_METADATA(1, "GeoTIFF_Version", NULL);
        ADD_METADATA(2, "GeoTIFF_Key_Revision", ".");
        s->geotag_count   = tget_short(&s->gb, s->le);
        if (s->geotag_count > count / 4 - 1) {
            s->geotag_count = count / 4 - 1;
            av_log(s->avctx, AV_LOG_WARNING, "GeoTIFF key directory buffer shorter than specified\n");
        }
        if (bytestream2_get_bytes_left(&s->gb) < s->geotag_count * sizeof(int16_t) * 4)
            return -1;
        s->geotags = av_mallocz(sizeof(TiffGeoTag) * s->geotag_count);
        if (!s->geotags) {
            av_log(s->avctx, AV_LOG_ERROR, "Error allocating temporary buffer\n");
            return AVERROR(ENOMEM);
        }
        for (i = 0; i < s->geotag_count; i++) {
            s->geotags[i].key    = tget_short(&s->gb, s->le);
            s->geotags[i].type   = tget_short(&s->gb, s->le);
            s->geotags[i].count  = tget_short(&s->gb, s->le);

            if (!s->geotags[i].type)
                s->geotags[i].val  = get_geokey_val(s->geotags[i].key, tget_short(&s->gb, s->le));
            else
                s->geotags[i].offset = tget_short(&s->gb, s->le);
        }
        break;
    case TIFF_GEO_DOUBLE_PARAMS:
        if (count >= INT_MAX / sizeof(int64_t))
            return AVERROR_INVALIDDATA;
        if (bytestream2_get_bytes_left(&s->gb) < count * sizeof(int64_t))
            return AVERROR_INVALIDDATA;
        dp = av_malloc(count * sizeof(double));
        if (!dp) {
            av_log(s->avctx, AV_LOG_ERROR, "Error allocating temporary buffer\n");
            return AVERROR(ENOMEM);
        }
        for (i = 0; i < count; i++)
            dp[i] = tget_double(&s->gb, s->le);
        for (i = 0; i < s->geotag_count; i++) {
            if (s->geotags[i].type == TIFF_GEO_DOUBLE_PARAMS) {
                if (s->geotags[i].count == 0
                    || s->geotags[i].offset + s->geotags[i].count > count) {
                    av_log(s->avctx, AV_LOG_WARNING, "Invalid GeoTIFF key %d\n", s->geotags[i].key);
                } else {
                    char *ap = doubles2str(&dp[s->geotags[i].offset], s->geotags[i].count, ", ");
                    if (!ap) {
                        av_log(s->avctx, AV_LOG_ERROR, "Error allocating temporary buffer\n");
                        av_freep(&dp);
                        return AVERROR(ENOMEM);
                    }
                    s->geotags[i].val = ap;
                }
            }
        }
        av_freep(&dp);
        break;
    case TIFF_GEO_ASCII_PARAMS:
        pos = bytestream2_tell(&s->gb);
        for (i = 0; i < s->geotag_count; i++) {
            if (s->geotags[i].type == TIFF_GEO_ASCII_PARAMS) {
                if (s->geotags[i].count == 0
                    || s->geotags[i].offset +  s->geotags[i].count > count) {
                    av_log(s->avctx, AV_LOG_WARNING, "Invalid GeoTIFF key %d\n", s->geotags[i].key);
                } else {
                    char *ap;

                    bytestream2_seek(&s->gb, pos + s->geotags[i].offset, SEEK_SET);
                    if (bytestream2_get_bytes_left(&s->gb) < s->geotags[i].count)
                        return -1;
                    ap = av_malloc(s->geotags[i].count);
                    if (!ap) {
                        av_log(s->avctx, AV_LOG_ERROR, "Error allocating temporary buffer\n");
                        return AVERROR(ENOMEM);
                    }
                    bytestream2_get_bufferu(&s->gb, ap, s->geotags[i].count);
                    ap[s->geotags[i].count - 1] = '\0'; //replace the "|" delimiter with a 0 byte
                    s->geotags[i].val = ap;
                }
            }
        }
        break;
    case TIFF_ARTIST:
        ADD_METADATA(count, "artist", NULL);
        break;
    case TIFF_COPYRIGHT:
        ADD_METADATA(count, "copyright", NULL);
        break;
    case TIFF_DATE:
        ADD_METADATA(count, "date", NULL);
        break;
    case TIFF_DOCUMENT_NAME:
        ADD_METADATA(count, "document_name", NULL);
        break;
    case TIFF_HOST_COMPUTER:
        ADD_METADATA(count, "computer", NULL);
        break;
    case TIFF_IMAGE_DESCRIPTION:
        ADD_METADATA(count, "description", NULL);
        break;
    case TIFF_MAKE:
        ADD_METADATA(count, "make", NULL);
        break;
    case TIFF_MODEL:
        ADD_METADATA(count, "model", NULL);
        break;
    case TIFF_PAGE_NAME:
        ADD_METADATA(count, "page_name", NULL);
        break;
    case TIFF_PAGE_NUMBER:
        ADD_METADATA(count, "page_number", " / ");
        break;
    case TIFF_SOFTWARE_NAME:
        ADD_METADATA(count, "software", NULL);
        break;
    default:
        av_log(s->avctx, AV_LOG_DEBUG, "Unknown or unsupported tag %d/0X%0X\n",
               tag, tag);
    }
    bytestream2_seek(&s->gb, start, SEEK_SET);
    return 0;
}