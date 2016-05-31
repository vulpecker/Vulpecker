nsresult
CVE_2015_0834_firefox26_0_PeerConnectionImpl::ConvertRTCConfiguration(const JS::Value& aSrc,
                                            IceConfiguration *aDst,
                                            JSContext* aCx)
{
#ifdef MOZILLA_INTERNAL_API
  if (!aSrc.isObject()) {
    return NS_ERROR_FAILURE;
  }
  JSAutoCompartment ac(aCx, &aSrc.toObject());
  RTCConfiguration config;
  JS::Rooted<JS::Value> src(aCx, aSrc);
  if (!(config.Init(aCx, src) && config.mIceServers.WasPassed())) {
    return NS_ERROR_FAILURE;
  }
  for (uint32_t i = 0; i < config.mIceServers.Value().Length(); i++) {
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

    // TODO(jib@mozilla.com): Revisit once nsURI has STUN host+port (Bug 833509)
    int32_t port;
    nsAutoCString host;
    {
      uint32_t hostPos;
      int32_t hostLen;
      nsAutoCString path;
      rv = url->GetPath(path);
      NS_ENSURE_SUCCESS(rv, rv);

      // Tolerate '?transport=udp' by stripping it.
      int32_t questionmark = path.FindChar('?');
      if (questionmark >= 0) {
        path.SetLength(questionmark);
      }

      rv = net_GetAuthURLParser()->ParseAuthority(path.get(), path.Length(),
                                                  nullptr,  nullptr,
                                                  nullptr,  nullptr,
                                                  &hostPos,  &hostLen, &port);
      NS_ENSURE_SUCCESS(rv, rv);
      if (!hostLen) {
        return NS_ERROR_FAILURE;
      }
      if (hostPos > 1)  /* The username was removed */
        return NS_ERROR_FAILURE;
      path.Mid(host, hostPos, hostLen);
    }
    if (port == -1)
      port = (isStuns || isTurns)? 5349 : 3478;

    if (isTurn || isTurns) {
      NS_ConvertUTF16toUTF8 credential(server.mCredential);
      NS_ConvertUTF16toUTF8 username(server.mUsername);

      if (!aDst->addTurnServer(host.get(), port,
                               username.get(),
                               credential.get())) {
        return NS_ERROR_FAILURE;
      }
    } else {
      if (!aDst->addStunServer(host.get(), port)) {
        return NS_ERROR_FAILURE;
      }
    }
  }
#endif
  return NS_OK;
}