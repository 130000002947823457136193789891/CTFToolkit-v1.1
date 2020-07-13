#
# (C) Tenable Network Security
#
# 


if(description)
{
 script_id(11967);
 
 script_version("$Revision: 1.2 $");

 script_cve_id("CAN-2003-1030");
 script_bugtraq_id(8395, 9213);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"3042");
 }

 name["english"] = "DameWare Mini Remote Control < 3.73";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a version of DameWare Mini Remote Control
below 3.73.  Such versions suffer from several vulnerabilities,
including a buffer overflow that allows an unauthenticated remote
attacker to execute arbitrary code. 

See also : http://sh0dan.org/files/dwmrcs372.txt

Solution : Upgrade to DameWare Mini Remote Control version 3.73 or higher.
Risk factor : High";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for DameWare Mini Remote Control < 3.73";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);

 exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for the version of DameWare Mini RC installed.
key1 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{F275C4B9-0769-4BE9-BDDE-C40A0789623C}/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{F275C4B9-0769-4BE9-BDDE-C40A0789623C}/DisplayVersion";
if (get_kb_item(key1)) {
  ver = get_kb_item(key2);
  if (ver && ver =~ "^([0-2]|3\.([0-6]|7[0-2]))") security_warning(port);
}
