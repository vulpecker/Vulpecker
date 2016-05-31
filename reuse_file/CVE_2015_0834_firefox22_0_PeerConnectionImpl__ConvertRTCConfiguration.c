nsresult
CVE_2015_0834_firefox22_0_PeerConnectionImpl::ConvertRTCConfiguration(const JS::Value& aSrc,
                                            IceConfiguration *aDst,
                                            JSContext* aCx)
{
#ifdef MOZILLA_INTERNAL_API
  if (!aSrc.isObject()) {
    return NS_ERROR_FAILURE;
  }
  JSAutoCompartment ac(aCx, &aSrc.toObject());
  RTCConfiguration config;
  if (!(config.Init(aCx, nullptr, aSrc) && config.mIceServers.WasPassed())) {
    return NS_ERROR_FAILURE;
  }
  for (uint32_t i = 0; i < config.mIceServers.Value().Length(); i++) {
    // XXXbz once this moves to WebIDL, remove RTCConfiguration in DummyBinding.webidl.
    RTCIceServer& server = config.mIceServers.Value()[i];
    if (!server.mUrl.WasPassed()) {
      return NS_ERROR_FAILURE;
    }
    nsRefPtr<nsIURI> url;
    nsresult rv;
    rv = NS_NewURI(getter_AddRefs(url), server.mUrl.Value());
    NS_ENSURE_SUCCESS(rv, rv);
    bool isStun = false, isStuns = false, isTurn = false, isTurns = false;
    url->SchemeIs("stun", &isStun);
    url->SchemeIs("stuns", &isStuns);
    url->SchemeIs("turn", &isTurn);
    url->SchemeIs("turns", &isTurns);
    if (!(isStun || isStuns || isTurn || isTurns)) {
      return NS_ERROR_FAILURE;
    }
    nsAutoCString spec;
    rv = url->GetSpec(spec);
    NS_ENSURE_SUCCESS(rv, rv);
    if (!server.mCredential.IsEmpty()) {
      // TODO(jib@mozilla.com): Support username, credentials & TURN servers
      Warn(aCx, nsPrintfCString(ICE_PARSING
          ": Credentials not yet implemented. Omitting \"%s\"", spec.get()));
      continue;
    }
    if (isTurn || isTurns) {
      Warn(aCx, nsPrintfCString(ICE_PARSING
          ": TURN servers not yet supported. Treating as STUN: \"%s\"", spec.get()));
    }
    // TODO(jib@mozilla.com): Revisit once nsURI supports host and port on STUN
    int32_t port;
    nsAutoCString host;
    {
      uint32_t hostPos;
      int32_t hostLen;
      nsAutoCString path;
      rv = url->GetPath(path);
      NS_ENSURE_SUCCESS(rv, rv);
      rv = net_GetAuthURLParser()->ParseAuthority(path.get(), path.Length(),
                                                  nullptr,  nullptr,
                                                  nullptr,  nullptr,
                                                  &hostPos,  &hostLen, &port);
      NS_ENSURE_SUCCESS(rv, rv);
      if (!hostLen) {
        return NS_ERROR_FAILURE;
      }
      path.Mid(host, hostPos, hostLen);
    }
    if (port == -1)
      port = (isStuns || isTurns)? 5349 : 3478;
    if (!aDst->addServer(host.get(), port)) {
      Warn(aCx, nsPrintfCString(ICE_PARSING
          ": FQDN not yet implemented (only IP-#s). Omitting \"%s\"", spec.get()));
    }
  }
#endif
  return NS_OK;
}