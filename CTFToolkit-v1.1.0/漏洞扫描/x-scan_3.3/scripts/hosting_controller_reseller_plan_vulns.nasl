#
# (C) Tenable Network Security
#


if (description) {
  script_id(18400);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(13806, 13816, 13829, 14080);

  name["english"] = "Hosting Controller 6.1 Hotfix 2.0 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its version number, the version of Hosting Controller on
the remote host suffers from multiple vulnerabilities:

  - An authenticated user can modify another user's profile, 
    even an admin's, recover his/her password, and then gain 
    access to the affected application as that user.

  - An authenticated user can view, edit, and even delete 
    reseller add-on plans. 

  - The scripts 'sendpassword.asp' and 'error.asp' are prone
    to cross-site scripting attacks.

See also : http://securitytracker.com/alerts/2005/May/1014062.html
           http://securitytracker.com/alerts/2005/May/1014071.html
           http://www.securityfocus.com/archive/1/403571/30/0/threaded
Solution : Apply Hotfix 2.1.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Hosting Controller 6.1 Hotfix 2.0";
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


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for the version of Hosting Controller installed.
name = kb_smb_name();
port = kb_smb_transport();
if (!get_port_state(port)) exit(0);
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.
soc = open_sock_tcp(port);
if (!soc) exit(0);
session_init(socket:soc, hostname:name);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(1);
}


# Determine the version / hotfix number of Hosting Controller.
key = "SOFTWARE\Advanced Communications\Nt Web Hosting Controller\General";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(value)) ver = value[1];

  value = RegQueryValue(handle:key_h, item:"LatestServicePack");
  if (!isnull(value)) hotfix = value[1];

  RegCloseKey(handle:key_h);

  # Check whether it's vulnerable.
  if (isnull(ver)) {
    if (log_verbosity > 1) {
      debug_print("can't determine version number of Hosting Controller install!");
    }
  }
  else {
    iver = split(ver, sep:'.', keep:FALSE);
    if (
      # nb: untested
      ( int(iver[0]) == 2002 ) ||
      ( int(iver[0]) < 6 ) ||
      ( 
        int(iver[0]) == 6 && 
        !isnull(iver[1]) && 
        (
          ( int(iver[1]) == 0 ) ||
          ( int(iver[1]) == 1 && !isnull(hotfix) && hotfix =~ "^([01]|2\.0)" )
        )
      )
     ) security_warning(port);
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
