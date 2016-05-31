
NS_IMETHODIMP
CVE_2013_0790_firefox10_0_2_nsPluginByteRangeStreamListener::OnStartRequest(nsIRequest *request, nsISupports *ctxt)
{
  nsresult rv;
  
  nsCOMPtr<nsIStreamListener> finalStreamListener = do_QueryReferent(mWeakPtrPluginStreamListenerPeer);
  if (!finalStreamListener)
    return NS_ERROR_FAILURE;
  
  nsPluginStreamListenerPeer *pslp =
    static_cast<nsPluginStreamListenerPeer*>(finalStreamListener.get());

  NS_ASSERTION(pslp->mRequests.IndexOfObject(GetBaseRequest(request)) != -1,
               "Untracked byte-range request?");
  
  nsCOMPtr<nsIStreamConverterService> serv = do_GetService(NS_STREAMCONVERTERSERVICE_CONTRACTID, &rv);
  if (NS_SUCCEEDED(rv)) {
    rv = serv->AsyncConvertData(MULTIPART_BYTERANGES,
                                "*/*",
                                finalStreamListener,
                                nsnull,
                                getter_AddRefs(mStreamConverter));
    if (NS_SUCCEEDED(rv)) {
      rv = mStreamConverter->OnStartRequest(request, ctxt);
      if (NS_SUCCEEDED(rv))
        return rv;
    }
  }
  mStreamConverter = 0;
  
  nsCOMPtr<nsIHttpChannel> httpChannel(do_QueryInterface(request));
  if (!httpChannel) {
    return NS_ERROR_FAILURE;
  }
  
  PRUint32 responseCode = 0;
  rv = httpChannel->GetResponseStatus(&responseCode);
  if (NS_FAILED(rv)) {
    return NS_ERROR_FAILURE;
  }
  
  if (responseCode != 200) {
    bool bWantsAllNetworkStreams = false;
    rv = pslp->GetPluginInstance()->GetValueFromPlugin(NPPVpluginWantsAllNetworkStreams,
                                                       &bWantsAllNetworkStreams);
    // If the call returned an error code make sure we still use our default value.
    if (NS_FAILED(rv)) {
      bWantsAllNetworkStreams = false;
    }

    if (!bWantsAllNetworkStreams){
      return NS_ERROR_FAILURE;
    }
  }
  
  // if server cannot continue with byte range (206 status) and sending us whole object (200 status)
  // reset this seekable stream & try serve it to plugin instance as a file
  mStreamConverter = finalStreamListener;
  mRemoveMagicNumber = true;
  
  rv = pslp->ServeStreamAsFile(request, ctxt);
  return rv;
}