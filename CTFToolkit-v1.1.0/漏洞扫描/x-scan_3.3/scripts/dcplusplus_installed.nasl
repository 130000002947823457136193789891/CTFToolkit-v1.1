#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18016);
  script_version("$Revision: 1.1 $");

  name["english"] = "DC++ Detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
DC++ is installed on the remote host.  DC++ is an open source client for
the Direct Connect peer-to-peer file-sharing protocol and may not be
suitable for use in a business environment. 

See also : http://dcplusplus.sourceforge.net/
Risk Factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for DC++";
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


# Look in the registry for evidence of DC++.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/DC++/DisplayName";
if (get_kb_item(key)) security_note(port);
