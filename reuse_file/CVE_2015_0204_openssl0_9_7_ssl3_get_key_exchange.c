
static int CVE_2015_0204_openssl0_9_7_ssl3_get_key_exchange(SSL *s)
	{
#ifndef OPENSSL_NO_RSA
	unsigned char *q,md_buf[EVP_MAX_MD_SIZE*2];
#endif
	EVP_MD_CTX md_ctx;
	unsigned char *param,*p;
	int al,i,j,param_len,ok;
	long n,alg;
	EVP_PKEY *pkey=NULL;
#ifndef OPENSSL_NO_RSA
	RSA *rsa=NULL;
#endif
#ifndef OPENSSL_NO_DH
	DH *dh=NULL;
#endif

	/* use same message size as in ssl3_get_certificate_request()
	 * as ServerKeyExchange message may be skipped */
	n=ssl3_get_message(s,
		SSL3_ST_CR_KEY_EXCH_A,
		SSL3_ST_CR_KEY_EXCH_B,
		-1,
		s->max_cert_list,
		&ok);

	if (!ok) return((int)n);

	if (s->s3->tmp.message_type != SSL3_MT_SERVER_KEY_EXCHANGE)
		{
		s->s3->tmp.reuse_message=1;
		return(1);
		}

	param=p=(unsigned char *)s->init_msg;

	if (s->session->sess_cert != NULL)
		{
#ifndef OPENSSL_NO_RSA
		if (s->session->sess_cert->peer_rsa_tmp != NULL)
			{
			RSA_free(s->session->sess_cert->peer_rsa_tmp);
			s->session->sess_cert->peer_rsa_tmp=NULL;
			}
#endif
#ifndef OPENSSL_NO_DH
		if (s->session->sess_cert->peer_dh_tmp)
			{
			DH_free(s->session->sess_cert->peer_dh_tmp);
			s->session->sess_cert->peer_dh_tmp=NULL;
			}
#endif
		}
	else
		{
		s->session->sess_cert=ssl_sess_cert_new();
		}

	param_len=0;
	alg=s->s3->tmp.new_cipher->algorithms;
	EVP_MD_CTX_init(&md_ctx);

#ifndef OPENSSL_NO_RSA
	if (alg & SSL_kRSA)
		{
		if ((rsa=RSA_new()) == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		n2s(p,i);
		param_len=i+2;
		if (param_len > n)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_RSA_MODULUS_LENGTH);
			goto f_err;
			}
		if (!(rsa->n=BN_bin2bn(p,i,rsa->n)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		n2s(p,i);
		param_len+=i+2;
		if (param_len > n)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_RSA_E_LENGTH);
			goto f_err;
			}
		if (!(rsa->e=BN_bin2bn(p,i,rsa->e)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;
		n-=param_len;

		/* this should be because we are using an export cipher */
		if (alg & SSL_aRSA)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
		else
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
			goto err;
			}
		s->session->sess_cert->peer_rsa_tmp=rsa;
		rsa=NULL;
		}
#else /* OPENSSL_NO_RSA */
	if (0)
		;
#endif
#ifndef OPENSSL_NO_DH
	else if (alg & SSL_kEDH)
		{
		if ((dh=DH_new()) == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_DH_LIB);
			goto err;
			}
		n2s(p,i);
		param_len=i+2;
		if (param_len > n)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_P_LENGTH);
			goto f_err;
			}
		if (!(dh->p=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		n2s(p,i);
		param_len+=i+2;
		if (param_len > n)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_G_LENGTH);
			goto f_err;
			}
		if (!(dh->g=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		n2s(p,i);
		param_len+=i+2;
		if (param_len > n)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_PUB_KEY_LENGTH);
			goto f_err;
			}
		if (!(dh->pub_key=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;
		n-=param_len;

#ifndef OPENSSL_NO_RSA
		if (alg & SSL_aRSA)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
#else
		if (0)
			;
#endif
#ifndef OPENSSL_NO_DSA
		else if (alg & SSL_aDSS)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_DSA_SIGN].x509);
#endif
		/* else anonymous DH, so no certificate or pkey. */

		s->session->sess_cert->peer_dh_tmp=dh;
		dh=NULL;
		}
	else if ((alg & SSL_kDHr) || (alg & SSL_kDHd))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER);
		goto f_err;
		}
#endif /* !OPENSSL_NO_DH */
	if (alg & SSL_aFZA)
		{
		al=SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER);
		goto f_err;
		}


	/* p points to the next byte, there are 'n' bytes left */


	/* if it was signed, check the signature */
	if (pkey != NULL)
		{
		n2s(p,i);
		n-=2;
		j=EVP_PKEY_size(pkey);

		if ((i != n) || (n > j) || (n <= 0))
			{
			/* wrong packet length */
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_WRONG_SIGNATURE_LENGTH);
			goto f_err;
			}

#ifndef OPENSSL_NO_RSA
		if (pkey->type == EVP_PKEY_RSA)
			{
			int num;

			j=0;
			q=md_buf;
			for (num=2; num > 0; num--)
				{
				EVP_DigestInit_ex(&md_ctx,(num == 2)
					?s->ctx->md5:s->ctx->sha1, NULL);
				EVP_DigestUpdate(&md_ctx,&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
				EVP_DigestUpdate(&md_ctx,&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);
				EVP_DigestUpdate(&md_ctx,param,param_len);
				EVP_DigestFinal_ex(&md_ctx,q,(unsigned int *)&i);
				q+=i;
				j+=i;
				}
			i=RSA_verify(NID_md5_sha1, md_buf, j, p, n,
								pkey->pkey.rsa);
			if (i < 0)
				{
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_RSA_DECRYPT);
				goto f_err;
				}
			if (i == 0)
				{
				/* bad signature */
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SIGNATURE);
				goto f_err;
				}
			}
		else
#endif
#ifndef OPENSSL_NO_DSA
			if (pkey->type == EVP_PKEY_DSA)
			{
			/* lets do DSS */
			EVP_VerifyInit_ex(&md_ctx,EVP_dss1(), NULL);
			EVP_VerifyUpdate(&md_ctx,&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
			EVP_VerifyUpdate(&md_ctx,&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);
			EVP_VerifyUpdate(&md_ctx,param,param_len);
			if (!EVP_VerifyFinal(&md_ctx,p,(int)n,pkey))
				{
				/* bad signature */
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SIGNATURE);
				goto f_err;
				}
			}
		else
#endif
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
			goto err;
			}
		}
	else
		{
		/* still data left over */
		if (!(alg & SSL_aNULL))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
			goto err;
			}
		if (n != 0)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_EXTRA_DATA_IN_MESSAGE);
			goto f_err;
			}
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_cleanup(&md_ctx);
	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	EVP_PKEY_free(pkey);
#ifndef OPENSSL_NO_RSA
	if (rsa != NULL)
		RSA_free(rsa);
#endif
#ifndef OPENSSL_NO_DH
	if (dh != NULL)
		DH_free(dh);
#endif
	EVP_MD_CTX_cleanup(&md_ctx);
	return(-1);
	}