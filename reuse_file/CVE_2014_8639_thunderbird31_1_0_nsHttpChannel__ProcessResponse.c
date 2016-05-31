
nsresult
CVE_2014_8639_thunderbird31_1_0_nsHttpChannel::ProcessResponse()
{
    nsresult rv;
    uint32_t httpStatus = mResponseHead->Status();

    // Gather data on whether the transaction and page (if this is
    // the initial page load) is being loaded with SSL.
    Telemetry::Accumulate(Telemetry::HTTP_TRANSACTION_IS_SSL,
                          mConnectionInfo->UsingSSL());
    if (mLoadFlags & LOAD_INITIAL_DOCUMENT_URI) {
        Telemetry::Accumulate(Telemetry::HTTP_PAGELOAD_IS_SSL,
                              mConnectionInfo->UsingSSL());
    }

    LOG(("CVE_2014_8639_thunderbird31_1_0_nsHttpChannel::ProcessResponse [this=%p httpStatus=%u]\n",
        this, httpStatus));

    if (mTransaction->ProxyConnectFailed()) {
        // Only allow 407 (authentication required) to continue
        if (httpStatus != 407)
            return ProcessFailedProxyConnect(httpStatus);
        // If proxy CONNECT response needs to complete, wait to process connection
        // for Strict-Transport-Security.
    } else {
        // Given a successful connection, process any STS data that's relevant.
        rv = ProcessSTSHeader();
        MOZ_ASSERT(NS_SUCCEEDED(rv), "ProcessSTSHeader failed, continuing load.");
    }

    MOZ_ASSERT(!mCachedContentIsValid);

    ProcessSSLInformation();

    // notify "http-on-examine-response" observers
    gHttpHandler->OnExamineResponse(this);

    SetCookie(mResponseHead->PeekHeader(nsHttp::Set_Cookie));

    // handle unused username and password in url (see bug 232567)
    if (httpStatus != 401 && httpStatus != 407) {
        if (!mAuthRetryPending)
            mAuthProvider->CheckForSuperfluousAuth();
        if (mCanceled)
            return CallOnStartRequest();

        // reset the authentication's current continuation state because our
        // last authentication attempt has been completed successfully
        mAuthProvider->Disconnect(NS_ERROR_ABORT);
        mAuthProvider = nullptr;
        LOG(("  continuation state has been reset"));
    }

    bool successfulReval = false;

    // handle different server response categories.  Note that we handle
    // caching or not caching of error pages in
    // nsHttpResponseHead::MustValidate; if you change this switch, update that
    // one
    switch (httpStatus) {
    case 200:
    case 203:
        // Per RFC 2616, 14.35.2, "A server MAY ignore the Range header".
        // So if a server does that and sends 200 instead of 206 that we
        // expect, notify our caller.
        // However, if we wanted to start from the beginning, let it go through
        if (mResuming && mStartPos != 0) {
            LOG(("Server ignored our Range header, cancelling [this=%p]\n", this));
            Cancel(NS_ERROR_NOT_RESUMABLE);
            rv = CallOnStartRequest();
            break;
        }
        // these can normally be cached
        rv = ProcessNormal();
        MaybeInvalidateCacheEntryForSubsequentGet();
        break;
    case 206:
        if (mCachedContentIsPartial) // an internal byte range request...
            rv = ProcessPartialContent();
        else {
            mCacheInputStream.CloseAndRelease();
            rv = ProcessNormal();
        }
        break;
    case 300:
    case 301:
    case 302:
    case 307:
    case 308:
    case 303:
#if 0
    case 305: // disabled as a security measure (see bug 187996).
#endif
        // don't store the response body for redirects
        MaybeInvalidateCacheEntryForSubsequentGet();
        PushRedirectAsyncFunc(&nsHttpChannel::ContinueProcessResponse);
        rv = AsyncProcessRedirection(httpStatus);
        if (NS_FAILED(rv)) {
            PopRedirectAsyncFunc(&nsHttpChannel::ContinueProcessResponse);
            LOG(("AsyncProcessRedirection failed [rv=%x]\n", rv));
            // don't cache failed redirect responses.
            if (mCacheEntry)
                mCacheEntry->AsyncDoom(nullptr);
            if (DoNotRender3xxBody(rv)) {
                mStatus = rv;
                DoNotifyListener();
            } else {
                rv = ContinueProcessResponse(rv);
            }
        }
        break;
    case 304:
        rv = ProcessNotModified();
        if (NS_FAILED(rv)) {
            LOG(("ProcessNotModified failed [rv=%x]\n", rv));
            mCacheInputStream.CloseAndRelease();
            rv = ProcessNormal();
        }
        else {
            successfulReval = true;
        }
        break;
    case 401:
    case 407:
        rv = mAuthProvider->ProcessAuthentication(
            httpStatus, mConnectionInfo->UsingSSL() &&
                        mTransaction->ProxyConnectFailed());
        if (rv == NS_ERROR_IN_PROGRESS)  {
            // authentication prompt has been invoked and result
            // is expected asynchronously
            mAuthRetryPending = true;
            if (httpStatus == 407 || mTransaction->ProxyConnectFailed())
                mProxyAuthPending = true;

            // suspend the transaction pump to stop receiving the
            // unauthenticated content data. We will throw that data
            // away when user provides credentials or resume the pump
            // when user refuses to authenticate.
            LOG(("Suspending the transaction, asynchronously prompting for credentials"));
            mTransactionPump->Suspend();
            rv = NS_OK;
        }
        else if (NS_FAILED(rv)) {
            LOG(("ProcessAuthentication failed [rv=%x]\n", rv));
            if (mTransaction->ProxyConnectFailed())
                return ProcessFailedProxyConnect(httpStatus);
            if (!mAuthRetryPending)
                mAuthProvider->CheckForSuperfluousAuth();
            rv = ProcessNormal();
        }
        else
            mAuthRetryPending = true; // see DoAuthRetry
        break;
    default:
        rv = ProcessNormal();
        MaybeInvalidateCacheEntryForSubsequentGet();
        break;
    }

    CacheDisposition cacheDisposition;
    if (!mDidReval)
        cacheDisposition = kCacheMissed;
    else if (successfulReval)
        cacheDisposition = kCacheHitViaReval;
    else
        cacheDisposition = kCacheMissedViaReval;

    AccumulateCacheHitTelemetry(cacheDisposition);

    return rv;
}