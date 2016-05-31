
NS_IMETHODIMP
CVE_2013_5597_firefox8_0_1_nsOfflineCachePendingUpdate::OnStateChange(nsIWebProgress* aWebProgress,
                                           nsIRequest *aRequest,
                                           PRUint32 progressStateFlags,
                                           nsresult aStatus)
{
    nsCOMPtr<nsIDOMDocument> updateDoc = do_QueryReferent(mDocument);
    if (!updateDoc) {
        // The document that scheduled this update has gone away,
        // we don't need to listen anymore.
        aWebProgress->RemoveProgressListener(this);
        NS_RELEASE_THIS();
        return NS_OK;
    }

    if (!(progressStateFlags & STATE_STOP)) {
        return NS_OK;
    }

    nsCOMPtr<nsIDOMWindow> window;
    aWebProgress->GetDOMWindow(getter_AddRefs(window));
    if (!window) return NS_OK;

    nsCOMPtr<nsIDOMDocument> progressDoc;
    window->GetDocument(getter_AddRefs(progressDoc));
    if (!progressDoc) return NS_OK;

    if (!SameCOMIdentity(progressDoc, updateDoc)) {
        return NS_OK;
    }

    LOG(("CVE_2013_5597_firefox8_0_1_nsOfflineCachePendingUpdate::OnStateChange [%p, doc=%p]",
         this, progressDoc.get()));

    // Only schedule the update if the document loaded successfully
    if (NS_SUCCEEDED(aStatus)) {
        nsCOMPtr<nsIOfflineCacheUpdate> update;
        mService->Schedule(mManifestURI, mDocumentURI,
                           updateDoc, window, getter_AddRefs(update));
    }

    aWebProgress->RemoveProgressListener(this);
    NS_RELEASE_THIS();

    return NS_OK;
}