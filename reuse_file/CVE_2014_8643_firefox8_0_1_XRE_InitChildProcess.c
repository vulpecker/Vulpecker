
nsresult
CVE_2014_8643_firefox8_0_1_XRE_InitChildProcess(int aArgc,
                     char* aArgv[],
                     GeckoProcessType aProcess)
{
  NS_ENSURE_ARG_MIN(aArgc, 2);
  NS_ENSURE_ARG_POINTER(aArgv);
  NS_ENSURE_ARG_POINTER(aArgv[0]);

  sChildProcessType = aProcess;

  // Complete 'task_t' exchange for Mac OS X. This structure has the same size
  // regardless of architecture so we don't have any cross-arch issues here.
#ifdef XP_MACOSX
  if (aArgc < 1)
    return 1;
  const char* const mach_port_name = aArgv[--aArgc];

  const int kTimeoutMs = 1000;

  MachSendMessage child_message(0);
  if (!child_message.AddDescriptor(mach_task_self())) {
    NS_WARNING("child AddDescriptor(mach_task_self()) failed.");
    return 1;
  }

  ReceivePort child_recv_port;
  mach_port_t raw_child_recv_port = child_recv_port.GetPort();
  if (!child_message.AddDescriptor(raw_child_recv_port)) {
    NS_WARNING("Adding descriptor to message failed");
    return 1;
  }

  MachPortSender child_sender(mach_port_name);
  kern_return_t err = child_sender.SendMessage(child_message, kTimeoutMs);
  if (err != KERN_SUCCESS) {
    NS_WARNING("child SendMessage() failed");
    return 1;
  }

  MachReceiveMessage parent_message;
  err = child_recv_port.WaitForMessage(&parent_message, kTimeoutMs);
  if (err != KERN_SUCCESS) {
    NS_WARNING("child WaitForMessage() failed");
    return 1;
  }

  if (parent_message.GetTranslatedPort(0) == MACH_PORT_NULL) {
    NS_WARNING("child GetTranslatedPort(0) failed");
    return 1;
  }
  err = task_set_bootstrap_port(mach_task_self(),
                                parent_message.GetTranslatedPort(0));
  if (err != KERN_SUCCESS) {
    NS_WARNING("child task_set_bootstrap_port() failed");
    return 1;
  }
#endif
  
#if defined(MOZ_CRASHREPORTER)
  if (aArgc < 1)
    return 1;
  const char* const crashReporterArg = aArgv[--aArgc];
  
#  if defined(XP_WIN) || defined(XP_MACOSX)
  // on windows and mac, |crashReporterArg| is the named pipe on which the
  // server is listening for requests, or "-" if crash reporting is
  // disabled.
  if (0 != strcmp("-", crashReporterArg) && 
      !XRE_SetRemoteExceptionHandler(crashReporterArg)) {
    // Bug 684322 will add better visibility into this condition
    NS_WARNING("Could not setup crash reporting\n");
  }
#  elif defined(OS_LINUX)
  // on POSIX, |crashReporterArg| is "true" if crash reporting is
  // enabled, false otherwise
  if (0 != strcmp("false", crashReporterArg) && 
      !XRE_SetRemoteExceptionHandler(NULL)) {
    // Bug 684322 will add better visibility into this condition
    NS_WARNING("Could not setup crash reporting\n");
  }
#  else
#    error "OOP crash reporting unsupported on this platform"
#  endif   
#endif // if defined(MOZ_CRASHREPORTER)

  gArgv = aArgv;
  gArgc = aArgc;

  SetupErrorHandling(aArgv[0]);
  
#if defined(MOZ_WIDGET_GTK2)
  g_thread_init(NULL);
#endif

#if defined(MOZ_WIDGET_QT)
  nsQAppInstance::AddRef();
#endif

  if (PR_GetEnv("MOZ_DEBUG_CHILD_PROCESS")) {
#ifdef OS_POSIX
      printf("\n\nCHILDCHILDCHILDCHILD\n  debug me @%d\n\n", getpid());
      sleep(30);
#elif defined(OS_WIN)
      printf("\n\nCHILDCHILDCHILDCHILD\n  debug me @%d\n\n", _getpid());
      Sleep(30000);
#endif
  }

  // child processes launched by GeckoChildProcessHost get this magic
  // argument appended to their command lines
  const char* const parentPIDString = aArgv[aArgc-1];
  NS_ABORT_IF_FALSE(parentPIDString, "NULL parent PID");
  --aArgc;

  char* end = 0;
  base::ProcessId parentPID = strtol(parentPIDString, &end, 10);
  NS_ABORT_IF_FALSE(!*end, "invalid parent PID");

  base::ProcessHandle parentHandle;
  mozilla::DebugOnly<bool> ok = base::OpenProcessHandle(parentPID, &parentHandle);
  NS_ABORT_IF_FALSE(ok, "can't open handle to parent");

#if defined(XP_WIN)
  // On Win7+, register the application user model id passed in by
  // parent. This insures windows created by the container properly
  // group with the parent app on the Win7 taskbar.
  const char* const appModelUserId = aArgv[aArgc-1];
  --aArgc;
  if (appModelUserId) {
    // '-' implies no support
    if (*appModelUserId != '-') {
      nsString appId;
      appId.AssignWithConversion(nsDependentCString(appModelUserId));
      // The version string is encased in quotes
      appId.Trim(NS_LITERAL_CSTRING("\"").get());
      // Set the id
      SetTaskbarGroupId(appId);
    }
  }
#endif

  base::AtExitManager exitManager;
  NotificationService notificationService;

  NS_LogInit();

  int rv = XRE_InitCommandLine(aArgc, aArgv);
  if (NS_FAILED(rv)) {
    NS_LogTerm();
    return NS_ERROR_FAILURE;
  }

  MessageLoop::Type uiLoopType;
  switch (aProcess) {
  case GeckoProcessType_Content:
      // Content processes need the XPCOM/chromium frankenventloop
      uiLoopType = MessageLoop::TYPE_MOZILLA_CHILD;
      break;
  default:
      uiLoopType = MessageLoop::TYPE_UI;
      break;
  }

  {
    // This is a lexical scope for the MessageLoop below.  We want it
    // to go out of scope before NS_LogTerm() so that we don't get
    // spurious warnings about XPCOM objects being destroyed from a
    // static context.

    // Associate this thread with a UI MessageLoop
    MessageLoop uiMessageLoop(uiLoopType);
    {
      nsAutoPtr<ProcessChild> process;

      switch (aProcess) {
      case GeckoProcessType_Default:
        NS_RUNTIMEABORT("This makes no sense");
        break;

      case GeckoProcessType_Plugin:
        process = new PluginProcessChild(parentHandle);
        break;

      case GeckoProcessType_Content:
        process = new ContentProcess(parentHandle);
        break;

      case GeckoProcessType_Jetpack:
        process = new JetpackProcessChild(parentHandle);
        break;

      case GeckoProcessType_IPDLUnitTest:
#ifdef MOZ_IPDL_TESTS
        process = new IPDLUnitTestProcessChild(parentHandle);
#else 
        NS_RUNTIMEABORT("rebuild with --enable-ipdl-tests");
#endif
        break;

      default:
        NS_RUNTIMEABORT("Unknown main thread class");
      }

      if (!process->Init()) {
        NS_LogTerm();
        return NS_ERROR_FAILURE;
      }

      // Run the UI event loop on the main thread.
      uiMessageLoop.MessageLoop::Run();

      // Allow ProcessChild to clean up after itself before going out of
      // scope and being deleted
      process->CleanUp();
      mozilla::Omnijar::CleanUp();
    }
  }

  NS_LogTerm();
  return XRE_DeinitCommandLine();
}