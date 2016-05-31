
static int msrle_decode_pal4(AVCodecContext *avctx, AVPicture *pic,
                              const uint8_t *data, int data_size)
{
    int stream_ptr = 0;
    unsigned char rle_code;
    unsigned char extra_byte, odd_pixel;
    unsigned char stream_byte;
    int pixel_ptr = 0;
    int row_dec = pic->linesize[0];
    int row_ptr = (avctx->height - 1) * row_dec;
    int frame_size = row_dec * avctx->height;
    int i;

    while (row_ptr >= 0) {
        FETCH_NEXT_STREAM_BYTE();
        rle_code = stream_byte;
        if (rle_code == 0) {
            /* fetch the next byte to see how to handle escape code */
            FETCH_NEXT_STREAM_BYTE();
            if (stream_byte == 0) {
                /* line is done, goto the next one */
                row_ptr -= row_dec;
                pixel_ptr = 0;
            } else if (stream_byte == 1) {
                /* decode is done */
                return 0;
            } else if (stream_byte == 2) {
                /* reposition frame decode coordinates */
                FETCH_NEXT_STREAM_BYTE();
                pixel_ptr += stream_byte;
                FETCH_NEXT_STREAM_BYTE();
                row_ptr -= stream_byte * row_dec;
        } else {
            // copy pixels from encoded stream
            odd_pixel =  stream_byte & 1;
            rle_code = (stream_byte + 1) / 2;
            extra_byte = rle_code & 0x01;
            if ((row_ptr + pixel_ptr + stream_byte > frame_size) ||
                (row_ptr < 0)) {
                av_log(avctx, AV_LOG_ERROR, " MS RLE: frame ptr just went out of bounds (1)\n");
                return -1;
            }

            for (i = 0; i < rle_code; i++) {
                if (pixel_ptr >= avctx->width)
                    break;
                FETCH_NEXT_STREAM_BYTE();
                pic->data[0][row_ptr + pixel_ptr] = stream_byte >> 4;
                pixel_ptr++;
                if (i + 1 == rle_code && odd_pixel)
                    break;
                if (pixel_ptr >= avctx->width)
                    break;
                pic->data[0][row_ptr + pixel_ptr] = stream_byte & 0x0F;
                pixel_ptr++;
            }

            // if the RLE code is odd, skip a byte in the stream
            if (extra_byte)
              stream_ptr++;
            }
        } else {
            // decode a run of data
            if ((row_ptr + pixel_ptr + stream_byte > frame_size) ||
                (row_ptr < 0)) {
                av_log(avctx, AV_LOG_ERROR, " MS RLE: frame ptr just went out of bounds (1)\n");
                return -1;
            }
            FETCH_NEXT_STREAM_BYTE();
            for (i = 0; i < rle_code; i++) {
                if (pixel_ptr >= avctx->width)
                    break;
                if ((i & 1) == 0)
                    pic->data[0][row_ptr + pixel_ptr] = stream_byte >> 4;
                else
                    pic->data[0][row_ptr + pixel_ptr] = stream_byte & 0x0F;
                pixel_ptr++;
            }
        }
    }

    /* one last sanity check on the way out */
    if (stream_ptr < data_size) {
        av_log(avctx, AV_LOG_ERROR, " MS RLE: ended frame decode with bytes left over (%d < %d)\n",
            stream_ptr, data_size);
        return -1;
    }

    return 0;
}