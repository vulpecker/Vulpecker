static int
CVE_2006_4790_gnutls1_4_3_decode_ber_digest_info (const gnutls_datum_t * info,
			gnutls_mac_algorithm_t * hash,
			opaque * digest, int *digest_size)
{
  ASN1_TYPE dinfo = ASN1_TYPE_EMPTY;
  int result;
  char str[1024];
  int len;

  if ((result = asn1_create_element (_gnutls_get_gnutls_asn (),
				     "GNUTLS.DigestInfo",
				     &dinfo)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&dinfo, info->data, info->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  len = sizeof (str) - 1;
  result = asn1_read_value (dinfo, "digestAlgorithm.algorithm", str, &len);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  *hash = _gnutls_x509_oid2mac_algorithm (str);

  if (*hash == GNUTLS_MAC_UNKNOWN)
    {

      _gnutls_x509_log ("verify.c: HASH OID: %s\n", str);

      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return GNUTLS_E_UNKNOWN_HASH_ALGORITHM;
    }

  len = sizeof (str) - 1;
  result = asn1_read_value (dinfo, "digestAlgorithm.parameters", NULL, &len);
  if (result != ASN1_ELEMENT_NOT_FOUND)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  result = asn1_read_value (dinfo, "digest", digest, digest_size);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  asn1_delete_structure (&dinfo);

  return 0;
}