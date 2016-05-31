SECStatus
CVE_2013_0791_firefox0_8_CERT_DecodeCertPackage(char *certbuf,
		       int certlen,
		       CERTImportCertificateFunc f,
		       void *arg)
{
    unsigned char *cp;
    int seqLen, seqLenLen;
    int cl;
    unsigned char *bincert = NULL, *certbegin = NULL, *certend = NULL;
    unsigned int binLen;
    char *ascCert = NULL;
    int asciilen;
    CERTCertificate *cert;
    SECItem certitem, oiditem;
    SECStatus rv;
    SECOidData *oiddata;
    SECItem *pcertitem = &certitem;
    
    if ( certbuf == NULL ) {
	return(SECFailure);
    }
    
    cert = 0;
    cp = (unsigned char *)certbuf;

    /* is a DER encoded certificate of some type? */
    if ( ( *cp  & 0x1f ) == SEC_ASN1_SEQUENCE ) {
	cp++;
	
	if ( *cp & 0x80) {
	    /* Multibyte length */
	    seqLenLen = cp[0] & 0x7f;
	    
	    switch (seqLenLen) {
	      case 4:
		seqLen = ((unsigned long)cp[1]<<24) |
		    ((unsigned long)cp[2]<<16) | (cp[3]<<8) | cp[4];
		break;
	      case 3:
		seqLen = ((unsigned long)cp[1]<<16) | (cp[2]<<8) | cp[3];
		break;
	      case 2:
		seqLen = (cp[1]<<8) | cp[2];
		break;
	      case 1:
		seqLen = cp[1];
		break;
	      default:
		/* indefinite length */
		seqLen = 0;
	    }
	    cp += ( seqLenLen + 1 );

	} else {
	    seqLenLen = 0;
	    seqLen = *cp;
	    cp++;
	}

	/* check entire length if definite length */
	if ( seqLen || seqLenLen ) {
	    if ( certlen != ( seqLen + seqLenLen + 2 ) ) {
		goto notder;
	    }
	}
	
	/* check the type string */
	/* netscape wrapped DER cert */
	if ( ( cp[0] == SEC_ASN1_OCTET_STRING ) &&
	    ( cp[1] == CERTIFICATE_TYPE_LEN ) &&
	    ( PORT_Strcmp((char *)&cp[2], CERTIFICATE_TYPE_STRING) ) ) {
	    
	    cp += ( CERTIFICATE_TYPE_LEN + 2 );

	    /* it had better be a certificate by now!! */
	    certitem.data = cp;
	    certitem.len = certlen - ( cp - (unsigned char *)certbuf );
	    
	    rv = (* f)(arg, &pcertitem, 1);
	    
	    return(rv);
	} else if ( cp[0] == SEC_ASN1_OBJECT_ID ) {
	    /* XXX - assume DER encoding of OID len!! */
	    oiditem.len = cp[1];
	    oiditem.data = (unsigned char *)&cp[2];
	    oiddata = SECOID_FindOID(&oiditem);
	    if ( oiddata == NULL ) {
		return(SECFailure);
	    }

	    certitem.data = (unsigned char*)certbuf;
	    certitem.len = certlen;
	    
	    switch ( oiddata->offset ) {
	      case SEC_OID_PKCS7_SIGNED_DATA:
		return(SEC_ReadPKCS7Certs(&certitem, f, arg));
		break;
	      case SEC_OID_NS_TYPE_CERT_SEQUENCE:
		return(SEC_ReadCertSequence(&certitem, f, arg));
		break;
	      default:
		break;
	    }
	    
	} else {
	    /* it had better be a certificate by now!! */
	    certitem.data = (unsigned char*)certbuf;
	    certitem.len = certlen;
	    
	    rv = (* f)(arg, &pcertitem, 1);
	    return(rv);
	}
    }

    /* now look for a netscape base64 ascii encoded cert */
notder:
    cp = (unsigned char *)certbuf;
    cl = certlen;
    certbegin = 0;
    certend = 0;

    /* find the beginning marker */
    while ( cl > sizeof(NS_CERT_HEADER) ) {
	if ( !PORT_Strncasecmp((char *)cp, NS_CERT_HEADER,
			     sizeof(NS_CERT_HEADER)-1) ) {
	    cp = cp + sizeof(NS_CERT_HEADER);
	    certbegin = cp;
	    break;
	}
	
	/* skip to next eol */
	do {
	    cp++;
	    cl--;
	} while ( ( *cp != '\n') && cl );

	/* skip all blank lines */
	while ( ( *cp == '\n') && cl ) {
	    cp++;
	    cl--;
	}
    }

    if ( certbegin ) {

	/* find the ending marker */
	while ( cl > sizeof(NS_CERT_TRAILER) ) {
	    if ( !PORT_Strncasecmp((char *)cp, NS_CERT_TRAILER,
				 sizeof(NS_CERT_TRAILER)-1) ) {
		certend = (unsigned char *)cp;
		break;
	    }

	    /* skip to next eol */
	    do {
		cp++;
		cl--;
	    } while ( ( *cp != '\n') && cl );

	    /* skip all blank lines */
	    while ( ( *cp == '\n') && cl ) {
		cp++;
		cl--;
	    }
	}
    }

    if ( certbegin && certend ) {

	/* Convert the ASCII data into a nul-terminated string */
	asciilen = certend - certbegin;
	ascCert = (char *)PORT_Alloc(asciilen+1);
	if (!ascCert) {
	    rv = SECFailure;
	    goto loser;
	}

	PORT_Memcpy(ascCert, certbegin, asciilen);
	ascCert[asciilen] = '\0';
	
	/* convert to binary */
	bincert = ATOB_AsciiToData(ascCert, &binLen);
	if (!bincert) {
	    rv = SECFailure;
	    goto loser;
	}

	/* now recurse to decode the binary */
	rv = CVE_2013_0791_firefox0_8_CERT_DecodeCertPackage((char *)bincert, binLen, f, arg);
	
    } else {
	rv = SECFailure;
    }

loser:

    if ( bincert ) {
	PORT_Free(bincert);
    }

    if ( ascCert ) {
	PORT_Free(ascCert);
    }

    return(rv);
}