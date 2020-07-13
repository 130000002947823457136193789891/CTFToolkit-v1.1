# 
# (C) Tenable Network Security
#

if(description)
{
 script_id(11921);
 script_bugtraq_id(9011);
 script_version("$Revision: 1.16 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0032");
 script_cve_id("CAN-2003-0812");
 if( defined_func("script_xref") ) script_xref(name:"CERT", value:"CA-2003-28");
 
 name["english"] = "Buffer Overflow in the Workstation Service (828749)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Windows host is vulnerable to a buffer overflow in its Workstation service
which may allow an attacker to execute arbitrary code on this host with SYSTEM
privileges. 


Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-049.mspx
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix 828749";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
  script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if (hotfix_check_sp(xp:2) > 0 )
  if ( hotfix_missing(name:"KB828035") > 0) 
	security_hole(get_kb_item("SMB/transport"));

if ( hotfix_check_sp(win2k:5) > 0 )
  if ( hotfix_missing(name:"KB828749") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));

