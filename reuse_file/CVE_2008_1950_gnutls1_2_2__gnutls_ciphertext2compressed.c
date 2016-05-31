int CVE_2008_1950_gnutls1_2_2__gnutls_ciphertext2compressed(gnutls_session_t session,
				  opaque * compress_data,
				  int compress_size,
				  gnutls_datum_t ciphertext, uint8 type)
{
    uint8 MAC[MAX_HASH_SIZE];
    uint16 c_length;
    uint8 pad;
    int length;
    mac_hd_t td;
    uint16 blocksize;
    int ret, i, pad_failed = 0;
    uint8 major, minor;
    gnutls_protocol_t ver;
    int hash_size =
	_gnutls_hash_get_algo_len(session->security_parameters.
				  read_mac_algorithm);

    ver = gnutls_protocol_get_version(session);
    minor = _gnutls_version_get_minor(ver);
    major = _gnutls_version_get_major(ver);

    blocksize = _gnutls_cipher_get_block_size(session->security_parameters.
					      read_bulk_cipher_algorithm);

    /* initialize MAC 
     */
    td = mac_init(session->security_parameters.read_mac_algorithm,
		  session->connection_state.read_mac_secret.data,
		  session->connection_state.read_mac_secret.size, ver);

    if (td == GNUTLS_MAC_FAILED
	&& session->security_parameters.read_mac_algorithm !=
	GNUTLS_MAC_NULL) {
	gnutls_assert();
	return GNUTLS_E_INTERNAL_ERROR;
    }


    /* actual decryption (inplace)
     */
    switch (_gnutls_cipher_is_block
	    (session->security_parameters.read_bulk_cipher_algorithm)) {
    case CIPHER_STREAM:
	if ((ret = _gnutls_cipher_decrypt(session->connection_state.
					  read_cipher_state,
					  ciphertext.data,
					  ciphertext.size)) < 0) {
	    gnutls_assert();
	    return ret;
	}

	length = ciphertext.size - hash_size;

	break;
    case CIPHER_BLOCK:
	if ((ciphertext.size < blocksize)
	    || (ciphertext.size % blocksize != 0)) {
	    gnutls_assert();
	    return GNUTLS_E_DECRYPTION_FAILED;
	}

	if ((ret = _gnutls_cipher_decrypt(session->connection_state.
					  read_cipher_state,
					  ciphertext.data,
					  ciphertext.size)) < 0) {
	    gnutls_assert();
	    return ret;
	}

	/* ignore the IV in TLS 1.1.
	 */
	if (session->security_parameters.version >= GNUTLS_TLS1_1) {
	    ciphertext.size -= blocksize;
	    ciphertext.data += blocksize;

	    if (ciphertext.size == 0) {
		gnutls_assert();
		return GNUTLS_E_DECRYPTION_FAILED;
	    }
	}

	pad = ciphertext.data[ciphertext.size - 1] + 1;	/* pad */

	length = ciphertext.size - hash_size - pad;

	if (pad > ciphertext.size - hash_size) {
	    gnutls_assert();
	    /* We do not fail here. We check below for the
	     * the pad_failed. If zero means success.
	     */
	    pad_failed = GNUTLS_E_DECRYPTION_FAILED;
	}

	/* Check the pading bytes (TLS 1.x)
	 */
	if (ver >= GNUTLS_TLS1)
	    for (i = 2; i < pad; i++) {
		if (ciphertext.data[ciphertext.size - i] !=
		    ciphertext.data[ciphertext.size - 1])
		    pad_failed = GNUTLS_E_DECRYPTION_FAILED;
	    }

	break;
    default:
	gnutls_assert();
	return GNUTLS_E_INTERNAL_ERROR;
    }

    if (length < 0)
	length = 0;
    c_length = _gnutls_conv_uint16((uint16) length);

    /* Pass the type, version, length and compressed through
     * MAC.
     */
    if (td != GNUTLS_MAC_FAILED) {
	_gnutls_hmac(td,
		     UINT64DATA(session->connection_state.
				read_sequence_number), 8);

	_gnutls_hmac(td, &type, 1);
	if (ver >= GNUTLS_TLS1) {	/* TLS 1.x */
	    _gnutls_hmac(td, &major, 1);
	    _gnutls_hmac(td, &minor, 1);
	}
	_gnutls_hmac(td, &c_length, 2);

	if (length > 0)
	    _gnutls_hmac(td, ciphertext.data, length);

	mac_deinit(td, MAC, ver);
    }

    /* This one was introduced to avoid a timing attack against the TLS
     * 1.0 protocol.
     */
    if (pad_failed != 0)
	return pad_failed;

    /* HMAC was not the same. 
     */
    if (memcmp(MAC, &ciphertext.data[length], hash_size) != 0) {
	gnutls_assert();
	return GNUTLS_E_DECRYPTION_FAILED;
    }

    /* copy the decrypted stuff to compress_data.
     */
    if (compress_size < length) {
	gnutls_assert();
	return GNUTLS_E_INTERNAL_ERROR;
    }
    memcpy(compress_data, ciphertext.data, length);

    return length;
}