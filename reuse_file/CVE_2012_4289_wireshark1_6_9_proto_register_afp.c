
void
proto_register_afp(void)
{

	static hf_register_info hf[] = {
		{ &hf_afp_command,
		  { "Command",      "afp.command",
		    FT_UINT8, BASE_DEC|BASE_EXT_STRING, &CommandCode_vals_ext, 0x0,
		    "AFP function", HFILL }},

		{ &hf_afp_pad,
		  { "Pad",    	"afp.pad",
		    FT_NONE,   BASE_NONE, NULL, 0,
		    "Pad Byte",	HFILL }},

		{ &hf_afp_AFPVersion,
		  { "AFP Version",  "afp.AFPVersion",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    "Client AFP version", HFILL }},

		{ &hf_afp_UAM,
		  { "UAM",          "afp.UAM",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    "User Authentication Method", HFILL }},

		{ &hf_afp_user,
		  { "User",         "afp.user",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_user_type,
		  { "Type",         "afp.user_type",
		    FT_UINT8, BASE_HEX, VALS(path_type_vals), 0,
		    "Type of user name", HFILL }},
		{ &hf_afp_user_len,
		  { "Len",  "afp.user_len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "User name length (unicode)", HFILL }},
		{ &hf_afp_user_name,
		  { "User",  "afp.user_name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "User name (unicode)", HFILL }},

		{ &hf_afp_passwd,
		  { "Password",     "afp.passwd",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_random,
		  { "Random number",         "afp.random",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "UAM random number", HFILL }},

		{ &hf_afp_response_to,
		  { "Response to",	"afp.response_to",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "This packet is a response to the packet in this frame", HFILL }},

		{ &hf_afp_time,
		  { "Time from request",	"afp.time",
		    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    "Time between Request and Response for AFP cmds", HFILL }},

		{ &hf_afp_response_in,
		  { "Response in",	"afp.response_in",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "The response to this packet is in this packet", HFILL }},

		{ &hf_afp_login_flags,
		  { "Flags",         "afp.afp_login_flags",
		    FT_UINT16, BASE_HEX, NULL, 0 /* 0x0FFF*/,
		    "Login flags", HFILL }},

		{ &hf_afp_vol_bitmap,
		  { "Bitmap",         "afp.vol_bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0 /* 0x0FFF*/,
		    "Volume bitmap", HFILL }},

		{ &hf_afp_vol_bitmap_Attributes,
		  { "Attributes",      "afp.vol_bitmap.attributes",
		    FT_BOOLEAN, 16, NULL, kFPVolAttributeBit,
		    "Volume attributes", HFILL }},

		{ &hf_afp_vol_attribute,
		  { "Attributes",         "afp.vol_attributes",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "Volume attributes", HFILL }},

		{ &hf_afp_vol_attribute_ReadOnly,
		  { "Read only",         "afp.vol_attribute.read_only",
		    FT_BOOLEAN, 16, NULL, kReadOnly,
		    "Read only volume", HFILL }},

		{ &hf_afp_vol_attribute_HasVolumePassword,
		  { "Volume password",         "afp.vol_attribute.passwd",
		    FT_BOOLEAN, 16, NULL, kHasVolumePassword,
		    "Has a volume password", HFILL }},

		{ &hf_afp_vol_attribute_SupportsFileIDs,
		  { "File IDs",         "afp.vol_attribute.fileIDs",
		    FT_BOOLEAN, 16, NULL, kSupportsFileIDs,
		    "Supports file IDs", HFILL }},

		{ &hf_afp_vol_attribute_SupportsCatSearch,
		  { "Catalog search",         "afp.vol_attribute.cat_search",
		    FT_BOOLEAN, 16, NULL, kSupportsCatSearch,
		    "Supports catalog search operations", HFILL }},

		{ &hf_afp_vol_attribute_SupportsBlankAccessPrivs,
		  { "Blank access privileges",         "afp.vol_attribute.blank_access_privs",
		    FT_BOOLEAN, 16, NULL, kSupportsBlankAccessPrivs,
		    "Supports blank access privileges", HFILL }},

		{ &hf_afp_vol_attribute_SupportsUnixPrivs,
		  { "UNIX access privileges",         "afp.vol_attribute.unix_privs",
		    FT_BOOLEAN, 16, NULL, kSupportsUnixPrivs,
		    "Supports UNIX access privileges", HFILL }},

		{ &hf_afp_vol_attribute_SupportsUTF8Names,
		  { "UTF-8 names",         "afp.vol_attribute.utf8_names",
		    FT_BOOLEAN, 16, NULL, kSupportsUTF8Names,
		    "Supports UTF-8 names", HFILL }},

		{ &hf_afp_vol_attribute_NoNetworkUserID,
		  { "No Network User ID",         "afp.vol_attribute.network_user_id",
		    FT_BOOLEAN, 16, NULL, kNoNetworkUserIDs,
		    NULL, HFILL }},

		{ &hf_afp_vol_attribute_DefaultPrivsFromParent,
		  { "Inherit parent privileges",         "afp.vol_attribute.inherit_parent_privs",
		    FT_BOOLEAN, 16, NULL, kDefaultPrivsFromParent,
		    NULL, HFILL }},

		{ &hf_afp_vol_attribute_NoExchangeFiles,
		  { "No exchange files",         "afp.vol_attribute.no_exchange_files",
		    FT_BOOLEAN, 16, NULL, kNoExchangeFiles,
		    "Exchange files not supported", HFILL }},

		{ &hf_afp_vol_attribute_SupportsExtAttrs,
		  { "Extended Attributes",         "afp.vol_attribute.extended_attributes",
		    FT_BOOLEAN, 16, NULL, kSupportsExtAttrs,
		    "Supports Extended Attributes", HFILL }},

		{ &hf_afp_vol_attribute_SupportsACLs,
		  { "ACLs",         "afp.vol_attribute.acls",
		    FT_BOOLEAN, 16, NULL, kSupportsACLs,
		    "Supports access control lists", HFILL }},

		{ &hf_afp_vol_attribute_CaseSensitive,
		  { "Case sensitive",         "afp.vol_attribute.case_sensitive",
		    FT_BOOLEAN, 16, NULL, kCaseSensitive,
		    "Supports case-sensitive filenames", HFILL }},

		{ &hf_afp_vol_attribute_SupportsTMLockSteal,
		  { "TM lock steal",         "afp.vol_attribute.TM_lock_steal",
		    FT_BOOLEAN, 16, NULL, kSupportsTMLockSteal,
		    "Supports Time Machine lock stealing", HFILL }},

		{ &hf_afp_vol_bitmap_Signature,
		  { "Signature",         "afp.vol_bitmap.signature",
		    FT_BOOLEAN, 16, NULL, kFPVolSignatureBit,
		    "Volume signature", HFILL }},

		{ &hf_afp_vol_bitmap_CreateDate,
		  { "Creation date",      "afp.vol_bitmap.create_date",
		    FT_BOOLEAN, 16, NULL, kFPVolCreateDateBit,
		    "Volume creation date", HFILL }},

		{ &hf_afp_vol_bitmap_ModDate,
		  { "Modification date",  "afp.vol_bitmap.mod_date",
		    FT_BOOLEAN, 16, NULL, kFPVolModDateBit,
		    "Volume modification date", HFILL }},

		{ &hf_afp_vol_bitmap_BackupDate,
		  { "Backup date",        "afp.vol_bitmap.backup_date",
		    FT_BOOLEAN, 16, NULL, kFPVolBackupDateBit,
		    "Volume backup date", HFILL }},

		{ &hf_afp_vol_bitmap_ID,
		  { "ID",         "afp.vol_bitmap.id",
		    FT_BOOLEAN, 16, NULL,  kFPVolIDBit,
		    "Volume ID", HFILL }},

		{ &hf_afp_vol_bitmap_BytesFree,
		  { "Bytes free",         "afp.vol_bitmap.bytes_free",
		    FT_BOOLEAN, 16, NULL,  kFPVolBytesFreeBit,
		    "Volume free bytes", HFILL }},

		{ &hf_afp_vol_bitmap_BytesTotal,
		  { "Bytes total",         "afp.vol_bitmap.bytes_total",
		    FT_BOOLEAN, 16, NULL,  kFPVolBytesTotalBit,
		    "Volume total bytes", HFILL }},

		{ &hf_afp_vol_bitmap_Name,
		  { "Name",         "afp.vol_bitmap.name",
		    FT_BOOLEAN, 16, NULL,  kFPVolNameBit,
		    "Volume name", HFILL }},

		{ &hf_afp_vol_bitmap_ExtBytesFree,
		  { "Extended bytes free",         "afp.vol_bitmap.ex_bytes_free",
		    FT_BOOLEAN, 16, NULL,  kFPVolExtBytesFreeBit,
		    "Volume extended (>2GB) free bytes", HFILL }},

		{ &hf_afp_vol_bitmap_ExtBytesTotal,
		  { "Extended bytes total",         "afp.vol_bitmap.ex_bytes_total",
		    FT_BOOLEAN, 16, NULL,  kFPVolExtBytesTotalBit,
		    "Volume extended (>2GB) total bytes", HFILL }},

		{ &hf_afp_vol_bitmap_BlockSize,
		  { "Block size",         "afp.vol_bitmap.block_size",
		    FT_BOOLEAN, 16, NULL,  kFPVolBlockSizeBit,
		    "Volume block size", HFILL }},

		{ &hf_afp_dir_bitmap_Attributes,
		  { "Attributes",         "afp.dir_bitmap.attributes",
		    FT_BOOLEAN, 16, NULL,  kFPAttributeBit,
		    "Return attributes if directory", HFILL }},

		{ &hf_afp_dir_bitmap_ParentDirID,
		  { "DID",         "afp.dir_bitmap.did",
		    FT_BOOLEAN, 16, NULL,  kFPParentDirIDBit,
		    "Return parent directory ID if directory", HFILL }},

		{ &hf_afp_dir_bitmap_CreateDate,
		  { "Creation date",         "afp.dir_bitmap.create_date",
		    FT_BOOLEAN, 16, NULL,  kFPCreateDateBit,
		    "Return creation date if directory", HFILL }},

		{ &hf_afp_dir_bitmap_ModDate,
		  { "Modification date",         "afp.dir_bitmap.mod_date",
		    FT_BOOLEAN, 16, NULL,  kFPModDateBit,
		    "Return modification date if directory", HFILL }},

		{ &hf_afp_dir_bitmap_BackupDate,
		  { "Backup date",         "afp.dir_bitmap.backup_date",
		    FT_BOOLEAN, 16, NULL,  kFPBackupDateBit,
		    "Return backup date if directory", HFILL }},

		{ &hf_afp_dir_bitmap_FinderInfo,
		  { "Finder info",         "afp.dir_bitmap.finder_info",
		    FT_BOOLEAN, 16, NULL,  kFPFinderInfoBit,
		    "Return finder info if directory", HFILL }},

		{ &hf_afp_dir_bitmap_LongName,
		  { "Long name",         "afp.dir_bitmap.long_name",
		    FT_BOOLEAN, 16, NULL,  kFPLongNameBit,
		    "Return long name if directory", HFILL }},

		{ &hf_afp_dir_bitmap_ShortName,
		  { "Short name",         "afp.dir_bitmap.short_name",
		    FT_BOOLEAN, 16, NULL,  kFPShortNameBit,
		    "Return short name if directory", HFILL }},

		{ &hf_afp_dir_bitmap_NodeID,
		  { "File ID",         "afp.dir_bitmap.fid",
		    FT_BOOLEAN, 16, NULL,  kFPNodeIDBit,
		    "Return file ID if directory", HFILL }},

		{ &hf_afp_dir_bitmap_OffspringCount,
		  { "Offspring count",         "afp.dir_bitmap.offspring_count",
		    FT_BOOLEAN, 16, NULL,  kFPOffspringCountBit,
		    "Return offspring count if directory", HFILL }},

		{ &hf_afp_dir_bitmap_OwnerID,
		  { "Owner id",         "afp.dir_bitmap.owner_id",
		    FT_BOOLEAN, 16, NULL,  kFPOwnerIDBit,
		    "Return owner id if directory", HFILL }},

		{ &hf_afp_dir_bitmap_GroupID,
		  { "Group id",         "afp.dir_bitmap.group_id",
		    FT_BOOLEAN, 16, NULL,  kFPGroupIDBit,
		    "Return group id if directory", HFILL }},

		{ &hf_afp_dir_bitmap_AccessRights,
		  { "Access rights",         "afp.dir_bitmap.access_rights",
		    FT_BOOLEAN, 16, NULL,  kFPAccessRightsBit,
		    "Return access rights if directory", HFILL }},

		{ &hf_afp_dir_bitmap_UTF8Name,
		  { "UTF-8 name",         "afp.dir_bitmap.UTF8_name",
		    FT_BOOLEAN, 16, NULL,  kFPUTF8NameBit,
		    "Return UTF-8 name if directory", HFILL }},

		{ &hf_afp_dir_bitmap_UnixPrivs,
		  { "UNIX privileges",         "afp.dir_bitmap.unix_privs",
		    FT_BOOLEAN, 16, NULL,  kFPUnixPrivsBit,
		    "Return UNIX privileges if directory", HFILL }},

		{ &hf_afp_dir_attribute_Invisible,
		  { "Invisible",         "afp.dir_attribute.invisible",
		    FT_BOOLEAN, 16, NULL,  kFPInvisibleBit,
		    "Directory is not visible", HFILL }},

		{ &hf_afp_dir_attribute_IsExpFolder,
		  { "Share point",         "afp.dir_attribute.share",
		    FT_BOOLEAN, 16, NULL,  kFPMultiUserBit,
		    "Directory is a share point", HFILL }},

		{ &hf_afp_dir_attribute_System,
		  { "System",         	 "afp.dir_attribute.system",
		    FT_BOOLEAN, 16, NULL,  kFPSystemBit,
		    "Directory is a system directory", HFILL }},

		{ &hf_afp_dir_attribute_Mounted,
		  { "Mounted",         "afp.dir_attribute.mounted",
		    FT_BOOLEAN, 16, NULL,  kFPDAlreadyOpenBit,
		    "Directory is mounted", HFILL }},

		{ &hf_afp_dir_attribute_InExpFolder,
		  { "Shared area",         "afp.dir_attribute.in_exported_folder",
		    FT_BOOLEAN, 16, NULL,  kFPRAlreadyOpenBit,
		    "Directory is in a shared area", HFILL }},

		{ &hf_afp_dir_attribute_BackUpNeeded,
		  { "Backup needed",         "afp.dir_attribute.backup_needed",
		    FT_BOOLEAN, 16, NULL,  kFPBackUpNeededBit,
		    "Directory needs to be backed up", HFILL }},

		{ &hf_afp_dir_attribute_RenameInhibit,
		  { "Rename inhibit",         "afp.dir_attribute.rename_inhibit",
		    FT_BOOLEAN, 16, NULL,  kFPRenameInhibitBit,
		    NULL, HFILL }},

		{ &hf_afp_dir_attribute_DeleteInhibit,
		  { "Delete inhibit",         "afp.dir_attribute.delete_inhibit",
		    FT_BOOLEAN, 16, NULL,  kFPDeleteInhibitBit,
		    NULL, HFILL }},

		{ &hf_afp_dir_attribute_SetClear,
		  { "Set",         "afp.dir_attribute.set_clear",
		    FT_BOOLEAN, 16, NULL,  kFPSetClearBit,
		    "Clear/set attribute", HFILL }},

		{ &hf_afp_file_bitmap_Attributes,
		  { "Attributes",         "afp.file_bitmap.attributes",
		    FT_BOOLEAN, 16, NULL,  kFPAttributeBit,
		    "Return attributes if file", HFILL }},

		{ &hf_afp_file_bitmap_ParentDirID,
		  { "DID",         "afp.file_bitmap.did",
		    FT_BOOLEAN, 16, NULL,  kFPParentDirIDBit,
		    "Return parent directory ID if file", HFILL }},

		{ &hf_afp_file_bitmap_CreateDate,
		  { "Creation date",         "afp.file_bitmap.create_date",
		    FT_BOOLEAN, 16, NULL,  kFPCreateDateBit,
		    "Return creation date if file", HFILL }},

		{ &hf_afp_file_bitmap_ModDate,
		  { "Modification date",         "afp.file_bitmap.mod_date",
		    FT_BOOLEAN, 16, NULL,  kFPModDateBit,
		    "Return modification date if file", HFILL }},

		{ &hf_afp_file_bitmap_BackupDate,
		  { "Backup date",         "afp.file_bitmap.backup_date",
		    FT_BOOLEAN, 16, NULL,  kFPBackupDateBit,
		    "Return backup date if file", HFILL }},

		{ &hf_afp_file_bitmap_FinderInfo,
		  { "Finder info",         "afp.file_bitmap.finder_info",
		    FT_BOOLEAN, 16, NULL,  kFPFinderInfoBit,
		    "Return finder info if file", HFILL }},

		{ &hf_afp_file_bitmap_LongName,
		  { "Long name",         "afp.file_bitmap.long_name",
		    FT_BOOLEAN, 16, NULL,  kFPLongNameBit,
		    "Return long name if file", HFILL }},

		{ &hf_afp_file_bitmap_ShortName,
		  { "Short name",         "afp.file_bitmap.short_name",
		    FT_BOOLEAN, 16, NULL,  kFPShortNameBit,
		    "Return short name if file", HFILL }},

		{ &hf_afp_file_bitmap_NodeID,
		  { "File ID",         "afp.file_bitmap.fid",
		    FT_BOOLEAN, 16, NULL,  kFPNodeIDBit,
		    "Return file ID if file", HFILL }},

		{ &hf_afp_file_bitmap_DataForkLen,
		  { "Data fork size",         "afp.file_bitmap.data_fork_len",
		    FT_BOOLEAN, 16, NULL,  kFPDataForkLenBit,
		    "Return data fork size if file", HFILL }},

		{ &hf_afp_file_bitmap_RsrcForkLen,
		  { "Resource fork size",         "afp.file_bitmap.resource_fork_len",
		    FT_BOOLEAN, 16, NULL,  kFPRsrcForkLenBit,
		    "Return resource fork size if file", HFILL }},

		{ &hf_afp_file_bitmap_ExtDataForkLen,
		  { "Extended data fork size",         "afp.file_bitmap.ex_data_fork_len",
		    FT_BOOLEAN, 16, NULL,  kFPExtDataForkLenBit,
		    "Return extended (>2GB) data fork size if file", HFILL }},

		{ &hf_afp_file_bitmap_LaunchLimit,
		  { "Launch limit",         "afp.file_bitmap.launch_limit",
		    FT_BOOLEAN, 16, NULL,  kFPLaunchLimitBit,
		    "Return launch limit if file", HFILL }},

		{ &hf_afp_file_bitmap_UTF8Name,
		  { "UTF-8 name",         "afp.file_bitmap.UTF8_name",
		    FT_BOOLEAN, 16, NULL,  kFPUTF8NameBit,
		    "Return UTF-8 name if file", HFILL }},

		{ &hf_afp_file_bitmap_ExtRsrcForkLen,
		  { "Extended resource fork size",         "afp.file_bitmap.ex_resource_fork_len",
		    FT_BOOLEAN, 16, NULL,  kFPExtRsrcForkLenBit,
		    "Return extended (>2GB) resource fork size if file", HFILL }},

		{ &hf_afp_file_bitmap_UnixPrivs,
		  { "UNIX privileges",    "afp.file_bitmap.unix_privs",
		    FT_BOOLEAN, 16, NULL,  kFPUnixPrivsBit,
		    "Return UNIX privileges if file", HFILL }},

		/* ---------- */
		{ &hf_afp_file_attribute_Invisible,
		  { "Invisible",         "afp.file_attribute.invisible",
		    FT_BOOLEAN, 16, NULL,  kFPInvisibleBit,
		    "File is not visible", HFILL }},

		{ &hf_afp_file_attribute_MultiUser,
		  { "Multi user",         "afp.file_attribute.multi_user",
		    FT_BOOLEAN, 16, NULL,  kFPMultiUserBit,
		    NULL, HFILL }},

		{ &hf_afp_file_attribute_System,
		  { "System",         	 "afp.file_attribute.system",
		    FT_BOOLEAN, 16, NULL,  kFPSystemBit,
		    "File is a system file", HFILL }},

		{ &hf_afp_file_attribute_DAlreadyOpen,
		  { "Data fork open",         "afp.file_attribute.df_open",
		    FT_BOOLEAN, 16, NULL,  kFPDAlreadyOpenBit,
		    "Data fork already open", HFILL }},

		{ &hf_afp_file_attribute_RAlreadyOpen,
		  { "Resource fork open",         "afp.file_attribute.rf_open",
		    FT_BOOLEAN, 16, NULL,  kFPRAlreadyOpenBit,
		    "Resource fork already open", HFILL }},

		{ &hf_afp_file_attribute_WriteInhibit,
		  { "Write inhibit",         "afp.file_attribute.write_inhibit",
		    FT_BOOLEAN, 16, NULL,  kFPWriteInhibitBit,
		    NULL, HFILL }},

		{ &hf_afp_file_attribute_BackUpNeeded,
		  { "Backup needed",         "afp.file_attribute.backup_needed",
		    FT_BOOLEAN, 16, NULL,  kFPBackUpNeededBit,
		    "File needs to be backed up", HFILL }},

		{ &hf_afp_file_attribute_RenameInhibit,
		  { "Rename inhibit",         "afp.file_attribute.rename_inhibit",
		    FT_BOOLEAN, 16, NULL,  kFPRenameInhibitBit,
		    NULL, HFILL }},

		{ &hf_afp_file_attribute_DeleteInhibit,
		  { "Delete inhibit",         "afp.file_attribute.delete_inhibit",
		    FT_BOOLEAN, 16, NULL,  kFPDeleteInhibitBit,
		    NULL, HFILL }},

		{ &hf_afp_file_attribute_CopyProtect,
		  { "Copy protect",         "afp.file_attribute.copy_protect",
		    FT_BOOLEAN, 16, NULL,  kFPCopyProtectBit,
		    NULL, HFILL }},

		{ &hf_afp_file_attribute_SetClear,
		  { "Set",         "afp.file_attribute.set_clear",
		    FT_BOOLEAN, 16, NULL,  kFPSetClearBit,
		    "Clear/set attribute", HFILL }},
		/* ---------- */

		{ &hf_afp_vol_name,
		  { "Volume",         "afp.vol_name",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    "Volume name", HFILL }},

		{ &hf_afp_vol_flag_passwd,
		  { "Password",         "afp.vol_flag_passwd",
		    FT_BOOLEAN, 8, NULL,  128,
		    "Volume is password-protected", HFILL }},

		{ &hf_afp_vol_flag_has_config,
		  { "Has config",         "afp.vol_flag_has_config",
		    FT_BOOLEAN, 8, NULL,  1,
		    "Volume has Apple II config info", HFILL }},

		{ &hf_afp_vol_id,
		  { "Volume id",         "afp.vol_id",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_vol_signature,
		  { "Signature",         "afp.vol_signature",
		    FT_UINT16, BASE_DEC, VALS(vol_signature_vals), 0x0,
		    "Volume signature", HFILL }},

		{ &hf_afp_vol_name_offset,
		  { "Volume name offset","afp.vol_name_offset",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Volume name offset in packet", HFILL }},

		{ &hf_afp_vol_creation_date,
		  { "Creation date",         "afp.vol_creation_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    "Volume creation date", HFILL }},

		{ &hf_afp_vol_modification_date,
		  { "Modification date",         "afp.vol_modification_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    "Volume modification date", HFILL }},

		{ &hf_afp_vol_backup_date,
		  { "Backup date",         "afp.vol_backup_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    "Volume backup date", HFILL }},

		{ &hf_afp_vol_bytes_free,
		  { "Bytes free",         "afp.vol_bytes_free",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Free space", HFILL }},

		{ &hf_afp_vol_bytes_total,
		  { "Bytes total",         "afp.vol_bytes_total",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Volume size", HFILL }},

		{ &hf_afp_vol_ex_bytes_free,
		  { "Extended bytes free",         "afp.vol_ex_bytes_free",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    "Extended (>2GB) free space", HFILL }},

		{ &hf_afp_vol_ex_bytes_total,
		  { "Extended bytes total",         "afp.vol_ex_bytes_total",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    "Extended (>2GB) volume size", HFILL }},

		{ &hf_afp_vol_block_size,
		  { "Block size",         "afp.vol_block_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Volume block size", HFILL }},

		{ &hf_afp_did,
		  { "DID",         "afp.did",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Parent directory ID", HFILL }},

		{ &hf_afp_dir_bitmap,
		  { "Directory bitmap",         "afp.dir_bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_dir_offspring,
		  { "Offspring",         "afp.dir_offspring",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Directory offspring", HFILL }},

		{ &hf_afp_dir_OwnerID,
		  { "Owner ID",         "afp.dir_owner_id",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Directory owner ID", HFILL }},

		{ &hf_afp_dir_GroupID,
		  { "Group ID",         "afp.dir_group_id",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Directory group ID", HFILL }},

		{ &hf_afp_creation_date,
		  { "Creation date",         "afp.creation_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_modification_date,
		  { "Modification date",         "afp.modification_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_backup_date,
		  { "Backup date",         "afp.backup_date",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_finder_info,
		  { "Finder info",         "afp.finder_info",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_long_name_offset,
		  { "Long name offset",    "afp.long_name_offset",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Long name offset in packet", HFILL }},

		{ &hf_afp_short_name_offset,
		  { "Short name offset",   "afp.short_name_offset",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Short name offset in packet", HFILL }},

		{ &hf_afp_unicode_name_offset,
		  { "Unicode name offset", "afp.unicode_name_offset",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Unicode name offset in packet", HFILL }},

		{ &hf_afp_unix_privs_uid,
		  { "UID",             "afp.unix_privs.uid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "User ID", HFILL }},

		{ &hf_afp_unix_privs_gid,
		  { "GID",             "afp.unix_privs.gid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Group ID", HFILL }},

		{ &hf_afp_unix_privs_permissions,
		  { "Permissions",     "afp.unix_privs.permissions",
		    FT_UINT32, BASE_OCT, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_unix_privs_ua_permissions,
		  { "User's access rights",     "afp.unix_privs.ua_permissions",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_file_id,
		  { "File ID",         "afp.file_id",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "File/directory ID", HFILL }},

		{ &hf_afp_file_DataForkLen,
		  { "Data fork size",         "afp.data_fork_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_file_RsrcForkLen,
		  { "Resource fork size",         "afp.resource_fork_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_file_ExtDataForkLen,
		  { "Extended data fork size",         "afp.ext_data_fork_len",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    "Extended (>2GB) data fork length", HFILL }},

		{ &hf_afp_file_ExtRsrcForkLen,
		  { "Extended resource fork size",         "afp.ext_resource_fork_len",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    "Extended (>2GB) resource fork length", HFILL }},

		{ &hf_afp_file_bitmap,
		  { "File bitmap",         "afp.file_bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_req_count,
		  { "Req count",         "afp.req_count",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Maximum number of structures returned", HFILL }},

		{ &hf_afp_start_index,
		  { "Start index",         "afp.start_index",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "First structure returned", HFILL }},

		{ &hf_afp_max_reply_size,
		  { "Reply size",         "afp.reply_size",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_start_index32,
		  { "Start index",         "afp.start_index32",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "First structure returned", HFILL }},

		{ &hf_afp_max_reply_size32,
		  { "Reply size",         "afp.reply_size32",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_file_flag,
		  { "Dir",         "afp.file_flag",
		    FT_BOOLEAN, 8, NULL, 0x80,
		    "Is a dir", HFILL }},

		{ &hf_afp_create_flag,
		  { "Hard create",         "afp.create_flag",
		    FT_BOOLEAN, 8, NULL, 0x80,
		    "Soft/hard create file", HFILL }},

		{ &hf_afp_request_bitmap_Attributes,
		  { "Attributes",         "afp.request_bitmap.attributes",
		    FT_BOOLEAN, 32, NULL,  kFPAttributeBit,
		    "Search attributes", HFILL }},

		{ &hf_afp_request_bitmap_ParentDirID,
		  { "DID",         "afp.request_bitmap.did",
		    FT_BOOLEAN, 32, NULL,  kFPParentDirIDBit,
		    "Search parent directory ID", HFILL }},

		{ &hf_afp_request_bitmap_CreateDate,
		  { "Creation date",         "afp.request_bitmap.create_date",
		    FT_BOOLEAN, 32, NULL,  kFPCreateDateBit,
		    "Search creation date", HFILL }},

		{ &hf_afp_request_bitmap_ModDate,
		  { "Modification date",         "afp.request_bitmap.mod_date",
		    FT_BOOLEAN, 32, NULL,  kFPModDateBit,
		    "Search modification date", HFILL }},

		{ &hf_afp_request_bitmap_BackupDate,
		  { "Backup date",         "afp.request_bitmap.backup_date",
		    FT_BOOLEAN, 32, NULL,  kFPBackupDateBit,
		    "Search backup date", HFILL }},

		{ &hf_afp_request_bitmap_FinderInfo,
		  { "Finder info",         "afp.request_bitmap.finder_info",
		    FT_BOOLEAN, 32, NULL,  kFPFinderInfoBit,
		    "Search finder info", HFILL }},

		{ &hf_afp_request_bitmap_LongName,
		  { "Long name",         "afp.request_bitmap.long_name",
		    FT_BOOLEAN, 32, NULL,  kFPLongNameBit,
		    "Search long name", HFILL }},

		{ &hf_afp_request_bitmap_DataForkLen,
		  { "Data fork size",         "afp.request_bitmap.data_fork_len",
		    FT_BOOLEAN, 32, NULL,  kFPDataForkLenBit,
		    "Search data fork size", HFILL }},

		{ &hf_afp_request_bitmap_OffspringCount,
		  { "Offspring count",         "afp.request_bitmap.offspring_count",
		    FT_BOOLEAN, 32, NULL,  kFPOffspringCountBit,
		    "Search offspring count", HFILL }},

		{ &hf_afp_request_bitmap_RsrcForkLen,
		  { "Resource fork size",         "afp.request_bitmap.resource_fork_len",
		    FT_BOOLEAN, 32, NULL,  kFPRsrcForkLenBit,
		    "Search resource fork size", HFILL }},

		{ &hf_afp_request_bitmap_ExtDataForkLen,
		  { "Extended data fork size",         "afp.request_bitmap.ex_data_fork_len",
		    FT_BOOLEAN, 32, NULL,  kFPExtDataForkLenBit,
		    "Search extended (>2GB) data fork size", HFILL }},

		{ &hf_afp_request_bitmap_UTF8Name,
		  { "UTF-8 name",         "afp.request_bitmap.UTF8_name",
		    FT_BOOLEAN, 32, NULL,  kFPUTF8NameBit,
		    "Search UTF-8 name", HFILL }},

		{ &hf_afp_request_bitmap_ExtRsrcForkLen,
		  { "Extended resource fork size",         "afp.request_bitmap.ex_resource_fork_len",
		    FT_BOOLEAN, 32, NULL,  kFPExtRsrcForkLenBit,
		    "Search extended (>2GB) resource fork size", HFILL }},

		{ &hf_afp_request_bitmap_PartialNames,
		  { "Match on partial names",         "afp.request_bitmap.partial_names",
		    FT_BOOLEAN, 32, NULL,  0x80000000,
		    NULL, HFILL }},

		{ &hf_afp_request_bitmap,
		  { "Request bitmap",         "afp.request_bitmap",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_struct_size,
		  { "Struct size",         "afp.struct_size",
		    FT_UINT8, BASE_DEC, NULL,0,
		    "Sizeof of struct", HFILL }},

		{ &hf_afp_struct_size16,
		  { "Struct size",         "afp.struct_size16",
		    FT_UINT16, BASE_DEC, NULL,0,
		    "Sizeof of struct", HFILL }},

		{ &hf_afp_flag,
		  { "From",         "afp.flag",
		    FT_UINT8, BASE_HEX, VALS(flag_vals), 0x80,
		    "Offset is relative to start/end of the fork", HFILL }},

		{ &hf_afp_dt_ref,
		  { "DT ref",         "afp.dt_ref",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Desktop database reference num", HFILL }},

		{ &hf_afp_ofork,
		  { "Fork",         "afp.ofork",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Open fork reference number", HFILL }},

		{ &hf_afp_offset,
		  { "Offset",         "afp.offset",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_rw_count,
		  { "Count",         "afp.rw_count",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Number of bytes to be read/written", HFILL }},

		{ &hf_afp_newline_mask,
		  { "Newline mask",  "afp.newline_mask",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "Value to AND bytes with when looking for newline", HFILL }},

		{ &hf_afp_newline_char,
		  { "Newline char",  "afp.newline_char",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "Value to compare ANDed bytes with when looking for newline", HFILL }},

		{ &hf_afp_last_written,
		  { "Last written",  "afp.last_written",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Offset of the last byte written", HFILL }},

		{ &hf_afp_actual_count,
		  { "Count",         "afp.actual_count",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Number of bytes returned by read/write", HFILL }},

		{ &hf_afp_ofork_len,
		  { "New length",         "afp.ofork_len",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_path_type,
		  { "Type",         "afp.path_type",
		    FT_UINT8, BASE_HEX, VALS(path_type_vals), 0,
		    "Type of names", HFILL }},

		{ &hf_afp_path_len,
		  { "Len",  "afp.path_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Path length", HFILL }},

		{ &hf_afp_path_unicode_len,
		  { "Len",  "afp.path_unicode_len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Path length (unicode)", HFILL }},

		{ &hf_afp_path_unicode_hint,
		  { "Unicode hint",  "afp.path_unicode_hint",
		    FT_UINT32, BASE_HEX|BASE_EXT_STRING, &unicode_hint_vals_ext, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_path_name,
		  { "Name",  "afp.path_name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Path name", HFILL }},

		{ &hf_afp_fork_type,
		  { "Resource fork",         "afp.fork_type",
		    FT_BOOLEAN, 8, NULL, 0x80,
		    "Data/resource fork", HFILL }},

		{ &hf_afp_access_mode,
		  { "Access mode",         "afp.access",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "Fork access mode", HFILL }},

		{ &hf_afp_access_read,
		  { "Read",         "afp.access.read",
		    FT_BOOLEAN, 8, NULL,  1,
		    "Open for reading", HFILL }},

		{ &hf_afp_access_write,
		  { "Write",         "afp.access.write",
		    FT_BOOLEAN, 8, NULL,  2,
		    "Open for writing", HFILL }},

		{ &hf_afp_access_deny_read,
		  { "Deny read",         "afp.access.deny_read",
		    FT_BOOLEAN, 8, NULL,  0x10,
		    NULL, HFILL }},

		{ &hf_afp_access_deny_write,
		  { "Deny write",         "afp.access.deny_write",
		    FT_BOOLEAN, 8, NULL,  0x20,
		    NULL, HFILL }},

		{ &hf_afp_comment,
		  { "Comment",         "afp.comment",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    "File/folder comment", HFILL }},

		{ &hf_afp_file_creator,
		  { "File creator",         "afp.file_creator",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_file_type,
		  { "File type",         "afp.file_type",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_icon_type,
		  { "Icon type",         "afp.icon_type",
		    FT_UINT8, BASE_HEX, NULL , 0,
		    NULL, HFILL }},

		{ &hf_afp_icon_length,
		  { "Size",         "afp.icon_length",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Size for icon bitmap", HFILL }},

		{ &hf_afp_icon_index,
		  { "Index",         "afp.icon_index",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Icon index in desktop database", HFILL }},

		{ &hf_afp_icon_tag,
		  { "Tag",         "afp.icon_tag",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Icon tag", HFILL }},

		{ &hf_afp_appl_index,
		  { "Index",         "afp.appl_index",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Application index", HFILL }},

		{ &hf_afp_appl_tag,
		  { "Tag",         "afp.appl_tag",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Application tag", HFILL }},

		{ &hf_afp_lock_op,
		  { "unlock",         "afp.lock_op",
		    FT_BOOLEAN, 8, NULL, 0x1,
		    "Lock/unlock op", HFILL }},

		{ &hf_afp_lock_from,
		  { "End",         "afp.lock_from",
		    FT_BOOLEAN, 8, NULL, 0x80,
		    "Offset is relative to the end of the fork", HFILL }},

		{ &hf_afp_lock_offset,
		  { "Offset",         "afp.lock_offset",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "First byte to be locked", HFILL }},

		{ &hf_afp_lock_len,
		  { "Length",         "afp.lock_len",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Number of bytes to be locked/unlocked", HFILL }},

		{ &hf_afp_lock_range_start,
		  { "Start",         "afp.lock_range_start",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "First byte locked/unlocked", HFILL }},

		{ &hf_afp_dir_ar,
		  { "Access rights",         "afp.dir_ar",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Directory access rights", HFILL }},

		{ &hf_afp_dir_ar_o_search,
		  { "Owner has search access",      "afp.dir_ar.o_search",
		    FT_BOOLEAN, 32, NULL, AR_O_SEARCH,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_o_read,
		  { "Owner has read access",        "afp.dir_ar.o_read",
		    FT_BOOLEAN, 32, NULL, AR_O_READ,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_o_write,
		  { "Owner has write access",       "afp.dir_ar.o_write",
		    FT_BOOLEAN, 32, NULL, AR_O_WRITE,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_g_search,
		  { "Group has search access",      "afp.dir_ar.g_search",
		    FT_BOOLEAN, 32, NULL, AR_G_SEARCH,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_g_read,
		  { "Group has read access",        "afp.dir_ar.g_read",
		    FT_BOOLEAN, 32, NULL, AR_G_READ,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_g_write,
		  { "Group has write access",       "afp.dir_ar.g_write",
		    FT_BOOLEAN, 32, NULL, AR_G_WRITE,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_e_search,
		  { "Everyone has search access",   "afp.dir_ar.e_search",
		    FT_BOOLEAN, 32, NULL, AR_E_SEARCH,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_e_read,
		  { "Everyone has read access",     "afp.dir_ar.e_read",
		    FT_BOOLEAN, 32, NULL, AR_E_READ,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_e_write,
		  { "Everyone has write access",    "afp.dir_ar.e_write",
		    FT_BOOLEAN, 32, NULL, AR_E_WRITE,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_u_search,
		  { "User has search access",   "afp.dir_ar.u_search",
		    FT_BOOLEAN, 32, NULL, AR_U_SEARCH,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_u_read,
		  { "User has read access",     "afp.dir_ar.u_read",
		    FT_BOOLEAN, 32, NULL, AR_U_READ,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_u_write,
		  { "User has write access",     "afp.dir_ar.u_write",
		    FT_BOOLEAN, 32, NULL, AR_U_WRITE,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_blank,
		  { "Blank access right",     "afp.dir_ar.blank",
		    FT_BOOLEAN, 32, NULL, AR_BLANK,
		    NULL, HFILL }},

		{ &hf_afp_dir_ar_u_own,
		  { "User is the owner",     "afp.dir_ar.u_owner",
		    FT_BOOLEAN, 32, NULL, AR_U_OWN,
		    "Current user is the directory owner", HFILL }},

		{ &hf_afp_server_time,
		  { "Server time",         "afp.server_time",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_cat_req_matches,
		  { "Max answers",         "afp.cat_req_matches",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Maximum number of matches to return.", HFILL }},

		{ &hf_afp_reserved,
		  { "Reserved",         "afp.reserved",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_cat_count,
		  { "Cat count",         "afp.cat_count",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Number of structures returned", HFILL }},

		{ &hf_afp_cat_position,
		  { "Position",         "afp.cat_position",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Reserved", HFILL }},

		{ &hf_afp_map_name_type,
		  { "Type",      "afp.map_name_type",
		    FT_UINT8, BASE_DEC|BASE_EXT_STRING, &map_name_type_vals_ext, 0x0,
		    "Map name type", HFILL }},

		{ &hf_afp_map_id_type,
		  { "Type",      "afp.map_id_type",
		    FT_UINT8, BASE_DEC|BASE_EXT_STRING, &map_id_type_vals_ext, 0x0,
		    "Map ID type", HFILL }},

		{ &hf_afp_map_id,
		  { "ID",             "afp.map_id",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "User/Group ID", HFILL }},

		{ &hf_afp_map_id_reply_type,
		  { "Reply type",      "afp.map_id_reply_type",
		    FT_UINT32, BASE_DEC, VALS(map_id_reply_type_vals), 0x0,
		    "Map ID reply type", HFILL }},

		{ &hf_afp_map_name,
		  { "Name",             "afp.map_name",
		    FT_UINT_STRING, BASE_NONE, NULL, 0x0,
		    "User/Group name", HFILL }},

		/* AFP 3.0 */
		{ &hf_afp_lock_offset64,
		  { "Offset",         "afp.lock_offset64",
		    FT_INT64, BASE_DEC, NULL, 0x0,
		    "First byte to be locked (64 bits)", HFILL }},

		{ &hf_afp_lock_len64,
		  { "Length",         "afp.lock_len64",
		    FT_INT64, BASE_DEC, NULL, 0x0,
		    "Number of bytes to be locked/unlocked (64 bits)", HFILL }},

		{ &hf_afp_lock_range_start64,
		  { "Start",         "afp.lock_range_start64",
		    FT_INT64, BASE_DEC, NULL, 0x0,
		    "First byte locked/unlocked (64 bits)", HFILL }},

		{ &hf_afp_offset64,
		  { "Offset",         "afp.offset64",
		    FT_INT64, BASE_DEC, NULL, 0x0,
		    "Offset (64 bits)", HFILL }},

		{ &hf_afp_rw_count64,
		  { "Count",         "afp.rw_count64",
		    FT_INT64, BASE_DEC, NULL, 0x0,
		    "Number of bytes to be read/written (64 bits)", HFILL }},

		{ &hf_afp_last_written64,
		  { "Last written",  "afp.last_written64",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    "Offset of the last byte written (64 bits)", HFILL }},

		{ &hf_afp_ofork_len64,
		  { "New length",         "afp.ofork_len64",
		    FT_INT64, BASE_DEC, NULL, 0x0,
		    "New length (64 bits)", HFILL }},

		{ &hf_afp_session_token_type,
		  { "Type",         "afp.session_token_type",
		    FT_UINT16, BASE_HEX|BASE_EXT_STRING, &token_type_vals_ext, 0x0,
		    "Session token type", HFILL }},

		/* FIXME FT_UINT32 in specs */
		{ &hf_afp_session_token_len,
		  { "Len",         "afp.session_token_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Session token length", HFILL }},

		{ &hf_afp_session_token_timestamp,
		  { "Time stamp",         "afp.session_token_timestamp",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Session time stamp", HFILL }},

		{ &hf_afp_session_token,
		  { "Token",         "afp.session_token",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Session token", HFILL }},

		{ &hf_afp_user_flag,
		  { "Flag",         "afp.user_flag",
		    FT_UINT8, BASE_HEX, VALS(user_flag_vals), 0x01,
		    "User Info flag", HFILL }},

		{ &hf_afp_user_ID,
		  { "User ID",         "afp.user_ID",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_group_ID,
		  { "Group ID",         "afp.group_ID",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_UUID,
		  { "UUID",         "afp.uuid",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_GRPUUID,
		  { "GRPUUID",         "afp.grpuuid",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Group UUID", HFILL }},

		{ &hf_afp_user_bitmap,
		  { "Bitmap",         "afp.user_bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "User Info bitmap", HFILL }},

		{ &hf_afp_user_bitmap_UID,
		  { "User ID",         "afp.user_bitmap.UID",
		    FT_BOOLEAN, 16, NULL, 0x01,
		    NULL, HFILL }},

		{ &hf_afp_user_bitmap_GID,
		  { "Primary group ID",         "afp.user_bitmap.GID",
		    FT_BOOLEAN, 16, NULL, 0x02,
		    NULL, HFILL }},

		{ &hf_afp_user_bitmap_UUID,
		  { "UUID",         "afp.user_bitmap.UUID",
		    FT_BOOLEAN, 16, NULL, 0x04,
		    NULL, HFILL }},

		{ &hf_afp_message_type,
		  { "Type",         "afp.message_type",
		    FT_UINT16, BASE_HEX, VALS(server_message_type), 0,
		    "Type of server message", HFILL }},

		{ &hf_afp_message_bitmap,
		  { "Bitmap",         "afp.message_bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "Message bitmap", HFILL }},

		{ &hf_afp_message_bitmap_REQ,
		  { "Request message",         "afp.message_bitmap.requested",
		    FT_BOOLEAN, 16, NULL, 0x01,
		    "Message Requested", HFILL }},

		{ &hf_afp_message_bitmap_UTF,
		  { "Message is UTF8",         "afp.message_bitmap.utf8",
		    FT_BOOLEAN, 16, NULL, 0x02,
		    NULL, HFILL }},

		{ &hf_afp_message_len,
		  { "Len",         "afp.message_length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Message length", HFILL }},

		{ &hf_afp_message,
		  { "Message",  "afp.message",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_reqcount64,
		  { "Count",         "afp.reqcount64",
		    FT_INT64, BASE_DEC, NULL, 0x0,
		    "Request Count (64 bits)", HFILL }},

		{ &hf_afp_extattr_bitmap,
		  { "Bitmap",         "afp.extattr_bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "Extended attributes bitmap", HFILL }},

		{ &hf_afp_extattr_bitmap_NoFollow,
		  { "No follow symlinks",         "afp.extattr_bitmap.nofollow",
		    FT_BOOLEAN, 16, NULL, 0x01,
		    "Do not follow symlink", HFILL }},

		{ &hf_afp_extattr_bitmap_Create,
		  { "Create",         "afp.extattr_bitmap.create",
		    FT_BOOLEAN, 16, NULL, 0x02,
		    "Create extended attribute", HFILL }},

		{ &hf_afp_extattr_bitmap_Replace,
		  { "Replace",         "afp.extattr_bitmap.replace",
		    FT_BOOLEAN, 16, NULL, 0x04,
		    "Replace extended attribute", HFILL }},

		{ &hf_afp_extattr_namelen,
		  { "Length",         "afp.extattr.namelen",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Extended attribute name length", HFILL }},

		{ &hf_afp_extattr_name,
		  { "Name",             "afp.extattr.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Extended attribute name", HFILL }},

		{ &hf_afp_extattr_len,
		  { "Length",         "afp.extattr.len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Extended attribute length", HFILL }},

		{ &hf_afp_extattr_data,
		  { "Data",         "afp.extattr.data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Extended attribute data", HFILL }},

		{ &hf_afp_extattr_req_count,
		  { "Request Count",         "afp.extattr.req_count",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Request Count.", HFILL }},

		{ &hf_afp_extattr_start_index,
		  { "Index",         "afp.extattr.start_index",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Start index", HFILL }},

		{ &hf_afp_extattr_reply_size,
		  { "Reply size",         "afp.extattr.reply_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		/* ACL control list bitmap */
		{ &hf_afp_access_bitmap,
		  { "Bitmap",         "afp.access_bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "Bitmap (reserved)", HFILL }},

		{ &hf_afp_acl_list_bitmap,
		  { "ACL bitmap",         "afp.acl_list_bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "ACL control list bitmap", HFILL }},

		{ &hf_afp_acl_list_bitmap_UUID,
		  { "UUID",         "afp.acl_list_bitmap.UUID",
		    FT_BOOLEAN, 16, NULL, kFileSec_UUID,
		    "User UUID", HFILL }},

		{ &hf_afp_acl_list_bitmap_GRPUUID,
		  { "GRPUUID",         "afp.acl_list_bitmap.GRPUUID",
		    FT_BOOLEAN, 16, NULL, kFileSec_GRPUUID,
		    "Group UUID", HFILL }},

		{ &hf_afp_acl_list_bitmap_ACL,
		  { "ACL",         "afp.acl_list_bitmap.ACL",
		    FT_BOOLEAN, 16, NULL, kFileSec_ACL,
		    NULL, HFILL }},

		{ &hf_afp_acl_list_bitmap_REMOVEACL,
		  { "Remove ACL",         "afp.acl_list_bitmap.REMOVEACL",
		    FT_BOOLEAN, 16, NULL, kFileSec_REMOVEACL,
		    NULL, HFILL }},

		{ &hf_afp_acl_list_bitmap_Inherit,
		  { "Inherit",         "afp.acl_list_bitmap.Inherit",
		    FT_BOOLEAN, 16, NULL, kFileSec_Inherit,
		    "Inherit ACL", HFILL }},

		{ &hf_afp_acl_entrycount,
		  { "Count",         "afp.acl_entrycount",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    "Number of ACL entries", HFILL }},

		{ &hf_afp_acl_flags,
		  { "ACL flags",         "afp.acl_flags",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_afp_ace_applicable,
		  { "ACE",         "afp.ace_applicable",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "ACE applicable", HFILL }},

		{ &hf_afp_ace_rights,
		  { "Rights",         "afp.ace_rights",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    "ACE flags", HFILL }},

		{ &hf_afp_acl_access_bitmap,
		  { "Bitmap",         "afp.acl_access_bitmap",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    "ACL access bitmap", HFILL }},

		{ &hf_afp_acl_access_bitmap_read_data,
		  { "Read/List",         "afp.acl_access_bitmap.read_data",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_READ_DATA,
		    "Read data / list directory", HFILL }},

		{ &hf_afp_acl_access_bitmap_write_data,
		  { "Write/Add file",         "afp.acl_access_bitmap.write_data",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_WRITE_DATA,
		    "Write data to a file / add a file to a directory", HFILL }},

		{ &hf_afp_acl_access_bitmap_execute,
		  { "Execute/Search",         "afp.acl_access_bitmap.execute",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_EXECUTE,
		    "Execute a program", HFILL }},

		{ &hf_afp_acl_access_bitmap_delete,
		  { "Delete",         "afp.acl_access_bitmap.delete",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_DELETE,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_append_data,
		  { "Append data/create subdir",         "afp.acl_access_bitmap.append_data",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_APPEND_DATA,
		    "Append data to a file / create a subdirectory", HFILL }},

		{ &hf_afp_acl_access_bitmap_delete_child,
		  { "Delete dir",         "afp.acl_access_bitmap.delete_child",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_DELETE_CHILD,
		    "Delete directory", HFILL }},

		{ &hf_afp_acl_access_bitmap_read_attrs,
		  { "Read attributes",         "afp.acl_access_bitmap.read_attrs",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_READ_ATTRIBUTES,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_write_attrs,
		  { "Write attributes",         "afp.acl_access_bitmap.write_attrs",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_WRITE_ATTRIBUTES,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_read_extattrs,
		  { "Read extended attributes", "afp.acl_access_bitmap.read_extattrs",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_READ_EXTATTRIBUTES,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_write_extattrs,
		  { "Write extended attributes", "afp.acl_access_bitmap.write_extattrs",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_WRITE_EXTATTRIBUTES,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_read_security,
		  { "Read security",         "afp.acl_access_bitmap.read_security",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_READ_SECURITY,
		    "Read access rights", HFILL }},

		{ &hf_afp_acl_access_bitmap_write_security,
		  { "Write security",         "afp.acl_access_bitmap.write_security",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_WRITE_SECURITY,
		    "Write access rights", HFILL }},

		{ &hf_afp_acl_access_bitmap_change_owner,
		  { "Change owner",         "afp.acl_access_bitmap.change_owner",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_CHANGE_OWNER,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_synchronize,
		  { "Synchronize",         "afp.acl_access_bitmap.synchronize",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_SYNCHRONIZE,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_generic_all,
		  { "Generic all",         "afp.acl_access_bitmap.generic_all",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_ALL,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_generic_execute,
		  { "Generic execute",         "afp.acl_access_bitmap.generic_execute",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_EXECUTE,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_generic_write,
		  { "Generic write",         "afp.acl_access_bitmap.generic_write",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_WRITE,
		    NULL, HFILL }},

		{ &hf_afp_acl_access_bitmap_generic_read,
		  { "Generic read",         "afp.acl_access_bitmap.generic_read",
		    FT_BOOLEAN, 32, NULL, KAUTH_VNODE_GENERIC_READ,
		    NULL, HFILL }},

		{ &hf_afp_ace_flags,
		  { "Flags",         "afp.ace_flags",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    "ACE flags", HFILL }},

		{ &hf_afp_ace_flags_allow,
		  { "Allow",         "afp.ace_flags.allow",
		    FT_BOOLEAN, 32, NULL, ACE_ALLOW,
		    "Allow rule", HFILL }},

		{ &hf_afp_ace_flags_deny,
		  { "Deny",         "afp.ace_flags.deny",
		    FT_BOOLEAN, 32, NULL, ACE_DENY,
		    "Deny rule", HFILL }},

		{ &hf_afp_ace_flags_inherited,
		  { "Inherited",         "afp.ace_flags.inherited",
		    FT_BOOLEAN, 32, NULL, ACE_INHERITED,
		    NULL, HFILL }},

		{ &hf_afp_ace_flags_fileinherit,
		  { "File inherit",         "afp.ace_flags.file_inherit",
		    FT_BOOLEAN, 32, NULL, ACE_FILE_INHERIT,
		    NULL, HFILL }},

		{ &hf_afp_ace_flags_dirinherit,
		  { "Dir inherit",         "afp.ace_flags.directory_inherit",
		    FT_BOOLEAN, 32, NULL, ACE_DIR_INHERIT,
		    NULL, HFILL }},

		{ &hf_afp_ace_flags_limitinherit,
		  { "Limit inherit",         "afp.ace_flags.limit_inherit",
		    FT_BOOLEAN, 32, NULL, ACE_LIMIT_INHERIT,
		    NULL, HFILL }},

		{ &hf_afp_ace_flags_onlyinherit,
		  { "Only inherit",         "afp.ace_flags.only_inherit",
		    FT_BOOLEAN, 32, NULL, ACE_ONLY_INHERIT,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_request_flags,
		  { "Flags",               "afp.spotlight.flags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Spotlight RPC Flags", HFILL }},

		{ &hf_afp_spotlight_request_command,
		  { "Command",               "afp.spotlight.command",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Spotlight RPC Command", HFILL }},

		{ &hf_afp_spotlight_request_reserved,
		  { "Padding",               "afp.spotlight.reserved",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Spotlight RPC Padding", HFILL }},

		{ &hf_afp_spotlight_volpath_client,
		  { "Client's volume path",               "afp.spotlight.volpath_client",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_volpath_server,
		  { "Server's volume path",               "afp.spotlight.volpath_server",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Servers's volume path", HFILL }},

		{ &hf_afp_spotlight_returncode,
		  { "Return code",               "afp.spotlight.return",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_volflags,
		  { "Volume flags",               "afp.spotlight.volflags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_reqlen,
		  { "Length",               "afp.spotlight.reqlen",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_toc_query_end,
		  { "End marker",               "afp.spotlight.query_end",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_spotlight_mdstring,
		  { "mdquery string",               "afp.spotlight.mds",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_afp_unknown,
		  { "Unknown parameter",         "afp.unknown",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_afp,
		&ett_afp_server_vol,
		&ett_afp_vol_list,
		&ett_afp_vol_flag,
		&ett_afp_vol_bitmap,
		&ett_afp_vol_attribute,
		&ett_afp_dir_bitmap,
		&ett_afp_file_bitmap,
		&ett_afp_unix_privs,
		&ett_afp_enumerate,
		&ett_afp_enumerate_line,
		&ett_afp_access_mode,
		&ett_afp_dir_attribute,
		&ett_afp_file_attribute,
		&ett_afp_path_name,
		&ett_afp_lock_flags,
		&ett_afp_dir_ar,
		&ett_afp_cat_search,
		&ett_afp_cat_r_bitmap,
		&ett_afp_cat_spec,
		&ett_afp_vol_did,
		&ett_afp_user_bitmap,
		&ett_afp_message_bitmap,
		&ett_afp_extattr_bitmap,
		&ett_afp_extattr_names,
		&ett_afp_acl_list_bitmap,
		&ett_afp_acl_access_bitmap,
		&ett_afp_ace_entries,
		&ett_afp_ace_entry,
		&ett_afp_ace_flags,
		&ett_afp_spotlight_queries,
		&ett_afp_spotlight_query_line,
		&ett_afp_spotlight_query,
		&ett_afp_spotlight_data,
		&ett_afp_spotlight_toc
	};

	proto_afp = proto_register_protocol("Apple Filing Protocol", "AFP", "afp");
	proto_register_field_array(proto_afp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_init_routine(afp_reinit);

	register_dissector("afp", dissect_afp, proto_afp);

	afp_tap = register_tap("afp");
}