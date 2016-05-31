bool
CVE_2012_3991_firefox15_0_1_nsJSObjWrapper::NP_SetProperty(NPObject *npobj, NPIdentifier id,
                               const NPVariant *value)
{
  NPP npp = NPPStack::Peek();
  JSContext *cx = GetJSContext(npp);

  if (!cx) {
    return false;
  }

  if (!npobj) {
    ThrowJSException(cx,
                     "Null npobj in CVE_2012_3991_firefox15_0_1_nsJSObjWrapper::NP_SetProperty!");

    return false;
  }

  nsJSObjWrapper *npjsobj = (nsJSObjWrapper *)npobj;
  JSBool ok = JS_FALSE;

  AutoCXPusher pusher(cx);
  JSAutoRequest ar(cx);
  AutoJSExceptionReporter reporter(cx);
  JSAutoEnterCompartment ac;

  if (!ac.enter(cx, npjsobj->mJSObj))
    return false;

  jsval v = NPVariantToJSVal(npp, cx, value);
  JS::AutoValueRooter tvr(cx, v);

  NS_ASSERTION(NPIdentifierIsInt(id) || NPIdentifierIsString(id),
               "id must be either string or int!\n");
  ok = ::JS_SetPropertyById(cx, npjsobj->mJSObj, NPIdentifierToJSId(id), &v);

  // return ok == JS_TRUE to quiet down compiler warning, even if
  // return ok is what we really want.
  return ok == JS_TRUE;
}