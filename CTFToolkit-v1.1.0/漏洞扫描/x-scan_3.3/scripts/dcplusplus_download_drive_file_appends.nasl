#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18012);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(13088);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15433");
  }

  name["english"] = "DC++ Download Drive File Appending Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its version number, the DC++ client installed on the
remote host is prone to a vulnerability that may let a remote user
append data to files anywhere on the drive on which DC++ is installed. 

Solution : Upgrade to DC++ 0.674 or greater.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for download drive file appending vulnerability in DC++";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);


# Look in the registry for the version of DC++ installed.
key1 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/DC++/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/DC++/DisplayVersion";
if (get_kb_item(key1)) {
  ver = get_kb_item(key2);
  if (ver && ver =~ "^0\.([0-5]|6([0-6]|7[0-3]))") {
    security_hole(port);
  }
}


