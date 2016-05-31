
static nsresult
CVE_2013_1705_firefox22_0_cryptojs_ReadArgsAndGenerateKey(JSContext *cx,
                                JS::Value *argv,
                                nsKeyPairInfo *keyGenType,
                                nsIInterfaceRequestor *uiCxt,
                                PK11SlotInfo **slot, bool willEscrow)
{
  JSString  *jsString;
  JSAutoByteString params, keyGenAlg;
  int    keySize;
  nsresult  rv;

  if (!JSVAL_IS_INT(argv[0])) {
    JS_ReportError(cx, "%s%s\n", JS_ERROR,
                   "passed in non-integer for key size");
    return NS_ERROR_FAILURE;
  }
  keySize = JSVAL_TO_INT(argv[0]);
  if (!JSVAL_IS_NULL(argv[1])) {
    jsString = JS_ValueToString(cx,argv[1]);
    NS_ENSURE_TRUE(jsString, NS_ERROR_OUT_OF_MEMORY);
    argv[1] = STRING_TO_JSVAL(jsString);
    params.encodeLatin1(cx, jsString);
    NS_ENSURE_TRUE(!!params, NS_ERROR_OUT_OF_MEMORY);
  }

  if (JSVAL_IS_NULL(argv[2])) {
    JS_ReportError(cx,"%s%s\n", JS_ERROR,
             "key generation type not specified");
    return NS_ERROR_FAILURE;
  }
  jsString = JS_ValueToString(cx, argv[2]);
  NS_ENSURE_TRUE(jsString, NS_ERROR_OUT_OF_MEMORY);
  argv[2] = STRING_TO_JSVAL(jsString);
  keyGenAlg.encodeLatin1(cx, jsString);
  NS_ENSURE_TRUE(!!keyGenAlg, NS_ERROR_OUT_OF_MEMORY);
  keyGenType->keyGenType = cryptojs_interpret_key_gen_type(keyGenAlg.ptr());
  if (keyGenType->keyGenType == invalidKeyGen) {
    JS_ReportError(cx, "%s%s%s", JS_ERROR,
                   "invalid key generation argument:",
                   keyGenAlg.ptr());
    goto loser;
  }
  if (!*slot) {
    *slot = nsGetSlotForKeyGen(keyGenType->keyGenType, uiCxt);
    if (!*slot)
      goto loser;
  }

  rv = cryptojs_generateOneKeyPair(cx,keyGenType,keySize,params.ptr(),uiCxt,
                                   *slot,willEscrow);

  if (rv != NS_OK) {
    JS_ReportError(cx,"%s%s%s", JS_ERROR,
                   "could not generate the key for algorithm ",
                   keyGenAlg.ptr());
    goto loser;
  }
  return NS_OK;
loser:
  return NS_ERROR_FAILURE;
}