#
# (C) Tenable Network Security
#
# 


if (description) {
  script_id(18616);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(14123);

  name["english"] = "Prevx Pro 2005 <= 1.0.0.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running Prevx Pro 2005, an intrusion protection
system for Windows. 

The installed version of Prevx Pro 2005 reportedly suffers from multiple
vulnerabilities that allow local attackers to bypass the application's
security features.

Solution : Unknown at this time.
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Prevx Pro 2005 <= 1.0.0.1";
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
key = "SOFTWARE\PREVX\Prevx Pro";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"DisplayName");
  if (!isnull(value)) name = value[1];

  value = RegQueryValue(handle:key_h, item:"BuildVersion");
  if (!isnull(value)) ver = value[1];

  RegCloseKey(handle:key_h);
}


# Check the version of Prevx Pro 2005 installed.
#
# nb: 16777217 <=> 0x1000001
if (!isnull(name) && !isnull(ver) && "Prevx Pro 2005" >< name && int(ver) <= 16777217) security_hole(port);


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
