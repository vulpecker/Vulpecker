nsresult
CVE_2014_1524_seamonkey2_25_nsXBLBinding::DoInitJSClass(JSContext *cx, JS::Handle<JSObject*> global,
                            JS::Handle<JSObject*> obj,
                            const nsAFlatCString& aClassName,
                            nsXBLPrototypeBinding* aProtoBinding,
                            JS::MutableHandle<JSObject*> aClassObject,
                            bool* aNew)
{
  // First ensure our JS class is initialized.
  nsAutoCString className(aClassName);
  nsAutoCString xblKey(aClassName);

  JSAutoCompartment ac(cx, global);

  JS::Rooted<JSObject*> parent_proto(cx, nullptr);
  nsXBLJSClass* c = nullptr;
  if (obj) {
    // Retrieve the current prototype of obj.
    if (!JS_GetPrototype(cx, obj, &parent_proto)) {
      return NS_ERROR_FAILURE;
    }
    if (parent_proto) {
      // We need to create a unique classname based on aClassName and
      // id.  Append a space (an invalid URI character) to ensure that
      // we don't have accidental collisions with the case when parent_proto is
      // null and aClassName ends in some bizarre numbers (yeah, it's unlikely).
      JS::Rooted<jsid> parent_proto_id(cx);
      if (!::JS_GetObjectId(cx, parent_proto, parent_proto_id.address())) {
        // Probably OOM
        return NS_ERROR_OUT_OF_MEMORY;
      }

      // One space, maybe "0x", at most 16 chars (on a 64-bit system) of long,
      // and a null-terminator (which PR_snprintf ensures is there even if the
      // string representation of what we're printing does not fit in the buffer
      // provided).
      char buf[20];
      if (sizeof(jsid) == 4) {
        PR_snprintf(buf, sizeof(buf), " %lx", parent_proto_id.get());
      } else {
        MOZ_ASSERT(sizeof(jsid) == 8);
        PR_snprintf(buf, sizeof(buf), " %llx", parent_proto_id.get());
      }
      xblKey.Append(buf);

      c = nsXBLService::getClass(xblKey);
      if (c) {
        className.Assign(c->name);
      } else {
        char buf[20];
        PR_snprintf(buf, sizeof(buf), " %llx", nsXBLJSClass::NewId());
        className.Append(buf);
      }
    }
  }

  JS::Rooted<JSObject*> proto(cx);
  JS::Rooted<JS::Value> val(cx);

  if (!::JS_LookupPropertyWithFlags(cx, global, className.get(), 0, &val))
    return NS_ERROR_OUT_OF_MEMORY;

  if (val.isObject()) {
    *aNew = false;
    proto = &val.toObject();
  } else {
    // We need to initialize the class.
    *aNew = true;

    nsCStringKey key(xblKey);
    if (!c) {
      c = nsXBLService::getClass(&key);
    }
    if (c) {
      // If c is on the LRU list, remove it now!
      if (c->isInList()) {
        c->remove();
        nsXBLService::gClassLRUListLength--;
      }
    } else {
      if (nsXBLService::gClassLRUList->isEmpty()) {
        // We need to create a struct for this class.
        c = new nsXBLJSClass(className, xblKey);
      } else {
        // Pull the least recently used class struct off the list.
        c = nsXBLService::gClassLRUList->popFirst();
        nsXBLService::gClassLRUListLength--;

        // Remove any mapping from the old name to the class struct.
        nsCStringKey oldKey(c->Key());
        (nsXBLService::gClassTable)->Remove(&oldKey);

        // Change the class name and we're done.
        nsMemory::Free((void*) c->name);
        c->name = ToNewCString(className);
        c->SetKey(xblKey);
      }

      // Add c to our table.
      (nsXBLService::gClassTable)->Put(&key, (void*)c);
    }

    // The prototype holds a strong reference to its class struct.
    c->Hold();

    // Make a new object prototyped by parent_proto and parented by global.
    proto = ::JS_InitClass(cx,                  // context
                           global,              // global object
                           parent_proto,        // parent proto 
                           c,                   // JSClass
                           nullptr,              // JSNative ctor
                           0,                   // ctor args
                           nullptr,              // proto props
                           nullptr,              // proto funcs
                           nullptr,              // ctor props (static)
                           nullptr);             // ctor funcs (static)
    if (!proto) {
      // This will happen if we're OOM or if the security manager
      // denies defining the new class...

      (nsXBLService::gClassTable)->Remove(&key);

      c->Drop();

      return NS_ERROR_OUT_OF_MEMORY;
    }

    // Keep this proto binding alive while we're alive.  Do this first so that
    // we can guarantee that in XBLFinalize this will be non-null.
    // Note that we can't just store aProtoBinding in the private and
    // addref/release the nsXBLDocumentInfo through it, because cycle
    // collection doesn't seem to work right if the private is not an
    // nsISupports.
    nsXBLDocumentInfo* docInfo = aProtoBinding->XBLDocumentInfo();
    ::JS_SetPrivate(proto, docInfo);
    NS_ADDREF(docInfo);

    ::JS_SetReservedSlot(proto, 0, PRIVATE_TO_JSVAL(aProtoBinding));
  }

  aClassObject.set(proto);

  if (obj) {
    // Set the prototype of our object to be the new class.
    if (!::JS_SetPrototype(cx, obj, proto)) {
      return NS_ERROR_FAILURE;
    }
  }

  return NS_OK;
}