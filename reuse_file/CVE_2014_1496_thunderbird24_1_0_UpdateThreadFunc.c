
static void
CVE_2014_1496_thunderbird24_1_0_UpdateThreadFunc(void *param)
{
  // open ZIP archive and process...
  int rv;
  if (sReplaceRequest) {
    rv = ProcessReplaceRequest();
  } else {
    NS_tchar dataFile[MAXPATHLEN];
    rv = GetUpdateFileName(dataFile, sizeof(dataFile)/sizeof(dataFile[0]));
    if (rv == OK) {
      rv = gArchiveReader.Open(dataFile);
    }

#ifdef MOZ_VERIFY_MAR_SIGNATURE
    if (rv == OK) {
      rv = gArchiveReader.VerifySignature();
    }

    if (rv == OK) {
      NS_tchar installDir[MAXPATHLEN];
      if (sBackgroundUpdate) {
        if (!GetInstallationDir(installDir)) {
          rv = NO_INSTALLDIR_ERROR;
        }
      } else {
        NS_tstrcpy(installDir, gDestinationPath);
      }
      if (rv == OK) {
        NS_tchar updateSettingsPath[MAX_TEXT_LEN];
        NS_tsnprintf(updateSettingsPath,
                     sizeof(updateSettingsPath) / sizeof(updateSettingsPath[0]),
                     NS_T("%s/update-settings.ini"), installDir);
        MARChannelStringTable MARStrings;
        if (ReadMARChannelIDs(updateSettingsPath, &MARStrings) != OK) {
          // If we can't read from update-settings.ini then we shouldn't impose
          // a MAR restriction.  Some installations won't even include this file.
          MARStrings.MARChannelID[0] = '\0';
        }

        rv = gArchiveReader.VerifyProductInformation(MARStrings.MARChannelID,
                                                     MOZ_APP_VERSION);
      }
    }
#endif

    if (rv == OK && sBackgroundUpdate && !sIsOSUpdate) {
      rv = CopyInstallDirToDestDir();
    }

    if (rv == OK) {
      rv = DoUpdate();
      gArchiveReader.Close();
    }
  }

  bool reportRealResults = true;
  if (sReplaceRequest && rv && !getenv("MOZ_NO_REPLACE_FALLBACK")) {
    // When attempting to replace the application, we should fall back
    // to non-staged updates in case of a failure.  We do this by
    // setting the status to pending, exiting the updater, and
    // launching the callback application.  The callback application's
    // startup path will see the pending status, and will start the
    // updater application again in order to apply the update without
    // staging.
    // The MOZ_NO_REPLACE_FALLBACK environment variable is used to
    // bypass this fallback, and is used in the updater tests.
    // The only special thing which we should do here is to remove the
    // staged directory as it won't be useful any more.
    NS_tchar installDir[MAXPATHLEN];
    if (GetInstallationDir(installDir)) {
      NS_tchar stageDir[MAXPATHLEN];
      NS_tsnprintf(stageDir, sizeof(stageDir)/sizeof(stageDir[0]),
#ifdef XP_MACOSX
                   NS_T("%s/Updated.app"),
#else
                   NS_T("%s/updated"),
#endif
                   installDir);

      ensure_remove_recursive(stageDir);
      WriteStatusFile(sUsingService ? "pending-service" : "pending");
      char processUpdates[] = "MOZ_PROCESS_UPDATES=";
      putenv(processUpdates); // We need to use -process-updates again in the tests
      reportRealResults = false; // pretend success
    }
  }

  if (reportRealResults) {
    if (rv) {
      LOG(("failed: %d", rv));
    }
    else {
#ifdef XP_MACOSX
      // If the update was successful we need to update the timestamp
      // on the top-level Mac OS X bundle directory so that Mac OS X's
      // Launch Services picks up any major changes. Here we assume that
      // the current working directory is the top-level bundle directory.
      char* cwd = getcwd(NULL, 0);
      if (cwd) {
        if (utimes(cwd, NULL) != 0) {
          LOG(("Couldn't set access/modification time on application bundle."));
        }
        free(cwd);
      }
      else {
        LOG(("Couldn't get current working directory for setting "
             "access/modification time on application bundle."));
      }
#endif

      LOG(("succeeded"));
    }
    WriteStatusFile(rv);
  }

  LOG(("calling QuitProgressUI"));
  QuitProgressUI();
}