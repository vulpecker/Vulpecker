
nsresult
CVE_2013_1709_thunderbird6_0_2_nsDocShell::AddToSessionHistory(nsIURI * aURI, nsIChannel * aChannel,
                                nsISupports* aOwner, PRBool aCloneChildren,
                                nsISHEntry ** aNewEntry)
{
    NS_PRECONDITION(aURI, "uri is null");
    NS_PRECONDITION(!aChannel || !aOwner, "Shouldn't have both set");

#if defined(PR_LOGGING) && defined(DEBUG)
    if (PR_LOG_TEST(gDocShellLog, PR_LOG_DEBUG)) {
        nsCAutoString spec;
        aURI->GetSpec(spec);

        nsCAutoString chanName;
        if (aChannel)
            aChannel->GetName(chanName);
        else
            chanName.AssignLiteral("<no channel>");

        PR_LOG(gDocShellLog, PR_LOG_DEBUG,
               ("nsDocShell[%p]::AddToSessionHistory(\"%s\", [%s])\n", this, spec.get(),
                chanName.get()));
    }
#endif

    nsresult rv = NS_OK;
    nsCOMPtr<nsISHEntry> entry;
    PRBool shouldPersist;

    shouldPersist = ShouldAddToSessionHistory(aURI);

    // Get a handle to the root docshell 
    nsCOMPtr<nsIDocShellTreeItem> root;
    GetSameTypeRootTreeItem(getter_AddRefs(root));     
    /*
     * If this is a LOAD_FLAGS_REPLACE_HISTORY in a subframe, we use
     * the existing SH entry in the page and replace the url and
     * other vitalities.
     */
    if (LOAD_TYPE_HAS_FLAGS(mLoadType, LOAD_FLAGS_REPLACE_HISTORY) &&
        root != static_cast<nsIDocShellTreeItem *>(this)) {
        // This is a subframe 
        entry = mOSHE;
        nsCOMPtr<nsISHContainer> shContainer(do_QueryInterface(entry));
        if (shContainer) {
            PRInt32 childCount = 0;
            shContainer->GetChildCount(&childCount);
            // Remove all children of this entry 
            for (PRInt32 i = childCount - 1; i >= 0; i--) {
                nsCOMPtr<nsISHEntry> child;
                shContainer->GetChildAt(i, getter_AddRefs(child));
                shContainer->RemoveChild(child);
            }  // for
        }  // shContainer
    }

    // Create a new entry if necessary.
    if (!entry) {
        entry = do_CreateInstance(NS_SHENTRY_CONTRACTID);

        if (!entry) {
            return NS_ERROR_OUT_OF_MEMORY;
        }
    }

    // Get the post data & referrer
    nsCOMPtr<nsIInputStream> inputStream;
    nsCOMPtr<nsIURI> referrerURI;
    nsCOMPtr<nsISupports> cacheKey;
    nsCOMPtr<nsISupports> owner = aOwner;
    PRBool expired = PR_FALSE;
    PRBool discardLayoutState = PR_FALSE;
    nsCOMPtr<nsICachingChannel> cacheChannel;
    if (aChannel) {
        cacheChannel = do_QueryInterface(aChannel);

        /* If there is a caching channel, get the Cache Key and store it
         * in SH.
         */
        if (cacheChannel) {
            cacheChannel->GetCacheKey(getter_AddRefs(cacheKey));
        }
        nsCOMPtr<nsIHttpChannel> httpChannel(do_QueryInterface(aChannel));
        
        // Check if the httpChannel is hiding under a multipartChannel
        if (!httpChannel) {
            GetHttpChannel(aChannel, getter_AddRefs(httpChannel));
        }
        if (httpChannel) {
            nsCOMPtr<nsIUploadChannel> uploadChannel(do_QueryInterface(httpChannel));
            if (uploadChannel) {
                uploadChannel->GetUploadStream(getter_AddRefs(inputStream));
            }
            httpChannel->GetReferrer(getter_AddRefs(referrerURI));

            discardLayoutState = ShouldDiscardLayoutState(httpChannel);
        }
        aChannel->GetOwner(getter_AddRefs(owner));
    }

    //Title is set in nsDocShell::SetTitle()
    entry->Create(aURI,              // uri
                  EmptyString(),     // Title
                  inputStream,       // Post data stream
                  nsnull,            // LayoutHistory state
                  cacheKey,          // CacheKey
                  mContentTypeHint,  // Content-type
                  owner,             // Channel or provided owner
                  mHistoryID,
                  mDynamicallyCreated);
    entry->SetReferrerURI(referrerURI);
    /* If cache got a 'no-store', ask SH not to store
     * HistoryLayoutState. By default, SH will set this
     * flag to PR_TRUE and save HistoryLayoutState.
     */    
    if (discardLayoutState) {
        entry->SetSaveLayoutStateFlag(PR_FALSE);
    }
    if (cacheChannel) {
        // Check if the page has expired from cache
        PRUint32 expTime = 0;
        cacheChannel->GetCacheTokenExpirationTime(&expTime);
        PRUint32 now = PRTimeToSeconds(PR_Now());
        if (expTime <=  now)
            expired = PR_TRUE;
    }
    if (expired)
        entry->SetExpirationStatus(PR_TRUE);


    if (root == static_cast<nsIDocShellTreeItem *>(this) && mSessionHistory) {
        // If we need to clone our children onto the new session
        // history entry, do so now.
        if (aCloneChildren && mOSHE) {
            PRUint32 cloneID;
            mOSHE->GetID(&cloneID);
            nsCOMPtr<nsISHEntry> newEntry;
            CloneAndReplace(mOSHE, this, cloneID, entry, PR_TRUE, getter_AddRefs(newEntry));
            NS_ASSERTION(entry == newEntry, "The new session history should be in the new entry");
        }

        // This is the root docshell
        if (LOAD_TYPE_HAS_FLAGS(mLoadType, LOAD_FLAGS_REPLACE_HISTORY)) {            
            // Replace current entry in session history.
            PRInt32  index = 0;   
            mSessionHistory->GetIndex(&index);
            nsCOMPtr<nsISHistoryInternal>   shPrivate(do_QueryInterface(mSessionHistory));
            // Replace the current entry with the new entry
            if (shPrivate)
                rv = shPrivate->ReplaceEntry(index, entry);          
        }
        else {
            // Add to session history
            nsCOMPtr<nsISHistoryInternal>
                shPrivate(do_QueryInterface(mSessionHistory));
            NS_ENSURE_TRUE(shPrivate, NS_ERROR_FAILURE);
            mSessionHistory->GetIndex(&mPreviousTransIndex);
            rv = shPrivate->AddEntry(entry, shouldPersist);
            mSessionHistory->GetIndex(&mLoadedTransIndex);
#ifdef DEBUG_PAGE_CACHE
            printf("Previous index: %d, Loaded index: %d\n\n",
                   mPreviousTransIndex, mLoadedTransIndex);
#endif
        }
    }
    else {  
        // This is a subframe.
        if (!mOSHE || !LOAD_TYPE_HAS_FLAGS(mLoadType,
                                           LOAD_FLAGS_REPLACE_HISTORY))
            rv = DoAddChildSHEntry(entry, mChildOffset, aCloneChildren);
    }

    // Return the new SH entry...
    if (aNewEntry) {
        *aNewEntry = nsnull;
        if (NS_SUCCEEDED(rv)) {
            *aNewEntry = entry;
            NS_ADDREF(*aNewEntry);
        }
    }

    return rv;
}