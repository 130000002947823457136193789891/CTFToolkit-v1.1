#
# (C) Tenable Network Security
#
# 


if (description) {
  script_id(18559);
  script_version("$Revision: 1.3 $");
  name["english"] = "Rhapsody Detection";
  script_name(english:name["english"]);
  desc["english"] = "
This script detects whether the remote host is running Rhapsody and,
if so, extracts its version number. 

Rhapsody is a music service and media player from RealNetworks.  See
http://www.rhapsody.com/ for more information.";

 
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects Rhapsody";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);
name = kb_smb_name();
port = kb_smb_transport();
if (!get_port_state(port)) exit(1);
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.
soc = open_sock_tcp(port);
if (!soc) exit(1);
session_init(socket:soc, hostname:name);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(1);
}


# Get the software's version.
key = "SOFTWARE\Wise Solutions\WiseUpdate\Apps\Listen Rhapsody";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(value)) ver = value[1];

  RegCloseKey(handle:key_h);
}


# Update KB and report findings.
if (ver) {
  set_kb_item(name:"SMB/Rhapsody/Version", value:ver);
  desc = "
Rhapsody version " + ver + " was detected on the remote host.

Rhapsody is a music service and media player from RealNetworks.  See
http://www.rhapsody.com/ for more information.

Risk Factor : None";
  security_note(port:port, data:desc);
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
