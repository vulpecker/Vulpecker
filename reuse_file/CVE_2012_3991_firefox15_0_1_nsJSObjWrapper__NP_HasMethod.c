bool
CVE_2012_3991_firefox15_0_1_nsJSObjWrapper::NP_HasMethod(NPObject *npobj, NPIdentifier id)
{
  NPP npp = NPPStack::Peek();
  JSContext *cx = GetJSContext(npp);

  if (!cx) {
    return false;
  }

  if (!npobj) {
    ThrowJSException(cx,
                     "Null npobj in CVE_2012_3991_firefox15_0_1_nsJSObjWrapper::NP_HasMethod!");

    return false;
  }

  nsJSObjWrapper *npjsobj = (nsJSObjWrapper *)npobj;

  AutoCXPusher pusher(cx);
  JSAutoRequest ar(cx);
  JSAutoEnterCompartment ac;

  if (!ac.enter(cx, npjsobj->mJSObj))
    return false;

  AutoJSExceptionReporter reporter(cx);

  jsval v;
  JSBool ok = GetProperty(cx, npjsobj->mJSObj, id, &v);

  return ok && !JSVAL_IS_PRIMITIVE(v) &&
    ::JS_ObjectIsFunction(cx, JSVAL_TO_OBJECT(v));
}