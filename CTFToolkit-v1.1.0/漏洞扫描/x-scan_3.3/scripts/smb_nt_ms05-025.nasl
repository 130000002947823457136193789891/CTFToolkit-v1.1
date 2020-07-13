#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18490);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(5560, 13947, 13946, 13943, 13941);
 script_cve_id("CAN-2005-1211", "CAN-2002-0648");

 
 script_version("$Revision: 1.4 $");
 name["english"] = "Cumulative Security Update for Internet Explorer (883939)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the IE cumulative security update 883939.

The remote version of IE is vulnerable to several flaws which may allow an attacker to
execute arbitrary code on the remote host.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms05-025.mspx
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 883939";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}


include("smb_hotfixes.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:5) <= 0 ) exit(0);

if ( hotfix_missing(name:"883939") > 0 )
	{
	 minorversion = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion");
	if ( "883939" >!< minorversion ) security_hole(get_kb_item("SMB/transport"));
	}


