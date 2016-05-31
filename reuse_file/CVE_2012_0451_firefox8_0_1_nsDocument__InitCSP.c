
nsresult
CVE_2012_0451_firefox8_0_1_nsDocument::InitCSP()
{
  if (CSPService::sCSPEnabled) {
    nsAutoString cspHeaderValue;
    nsAutoString cspROHeaderValue;

    this->GetHeaderData(nsGkAtoms::headerCSP, cspHeaderValue);
    this->GetHeaderData(nsGkAtoms::headerCSPReportOnly, cspROHeaderValue);

    PRBool system = PR_FALSE;
    nsIScriptSecurityManager *ssm = nsContentUtils::GetSecurityManager();

    if (NS_SUCCEEDED(ssm->IsSystemPrincipal(NodePrincipal(), &system)) && system) {
      // only makes sense to register new CSP if this document is not priviliged
      return NS_OK;
    }

    if (cspHeaderValue.IsEmpty() && cspROHeaderValue.IsEmpty()) {
      // no CSP header present, stop processing
      return NS_OK;
    }

#ifdef PR_LOGGING 
    PR_LOG(gCspPRLog, PR_LOG_DEBUG, ("CSP header specified for document %p", this));
#endif

    nsresult rv;
    nsCOMPtr<nsIContentSecurityPolicy> mCSP;
    mCSP = do_CreateInstance("@mozilla.org/contentsecuritypolicy;1", &rv);

    if (NS_FAILED(rv)) {
#ifdef PR_LOGGING 
      PR_LOG(gCspPRLog, PR_LOG_DEBUG, ("Failed to create CSP object: %x", rv));
#endif
      return rv;
    }

    // Store the request context for violation reports
    nsCOMPtr<nsIHttpChannel> httpChannel = do_QueryInterface(mChannel);
    mCSP->ScanRequestData(httpChannel);

    // Start parsing the policy
    nsCOMPtr<nsIURI> chanURI;
    mChannel->GetURI(getter_AddRefs(chanURI));

#ifdef PR_LOGGING 
    PR_LOG(gCspPRLog, PR_LOG_DEBUG, ("CSP Loaded"));
#endif

    // ReportOnly mode is enabled *only* if there are no regular-strength CSP
    // headers present.  If there are, then we ignore the ReportOnly mode and
    // toss a warning into the error console, proceeding with enforcing the
    // regular-strength CSP.
    if (cspHeaderValue.IsEmpty()) {
      mCSP->SetReportOnlyMode(true);
      mCSP->RefinePolicy(cspROHeaderValue, chanURI);
#ifdef PR_LOGGING 
      {
        PR_LOG(gCspPRLog, PR_LOG_DEBUG, 
                ("CSP (report only) refined, policy: \"%s\"", 
                  NS_ConvertUTF16toUTF8(cspROHeaderValue).get()));
      }
#endif
    } else {
      //XXX(sstamm): maybe we should post a warning when both read only and regular 
      // CSP headers are present.
      mCSP->RefinePolicy(cspHeaderValue, chanURI);
#ifdef PR_LOGGING 
      {
        PR_LOG(gCspPRLog, PR_LOG_DEBUG, 
               ("CSP refined, policy: \"%s\"",
                NS_ConvertUTF16toUTF8(cspHeaderValue).get()));
      }
#endif
    }

    // Check for frame-ancestor violation
    nsCOMPtr<nsIDocShell> docShell = do_QueryReferent(mDocumentContainer);
    if (docShell) {
        PRBool safeAncestry = false;

        // PermitsAncestry sends violation reports when necessary
        rv = mCSP->PermitsAncestry(docShell, &safeAncestry);
        NS_ENSURE_SUCCESS(rv, rv);

        if (!safeAncestry) {
#ifdef PR_LOGGING
            PR_LOG(gCspPRLog, PR_LOG_DEBUG, 
                   ("CSP doesn't like frame's ancestry, not loading."));
#endif
            // stop!  ERROR page!
            mChannel->Cancel(NS_ERROR_CSP_FRAME_ANCESTOR_VIOLATION);
        }
    }

    //Copy into principal
    nsIPrincipal* principal = GetPrincipal();

    if (principal) {
        principal->SetCsp(mCSP);
#ifdef PR_LOGGING
        PR_LOG(gCspPRLog, PR_LOG_DEBUG, 
                ("Inserted CSP into principal %p", principal));
    }
    else {
      PR_LOG(gCspPRLog, PR_LOG_DEBUG, 
              ("Couldn't copy CSP into absent principal %p", principal));
#endif
    }
  }
#ifdef PR_LOGGING
  else { //CSP was not enabled!
    PR_LOG(gCspPRLog, PR_LOG_DEBUG, 
           ("CSP is disabled, skipping CSP init for document %p", this));
  }
#endif
  return NS_OK;
}