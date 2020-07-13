#
# This script was written by Trevor Hemsley, by using smb_nt_ms03-005.nasl
# from Michael Scheidell as a template.
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(11413);
 script_bugtraq_id(7116);
 script_version("$Revision: 1.16 $");
 script_cve_id("CAN-2003-0109");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0005");

 name["english"] = "Unchecked Buffer in ntdll.dll (Q815021)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is vulnerable to a flaw in ntdll.dll
which may allow an attacker to gain system privileges,
by exploiting it thru, for instance, WebDAV in IIS5.0
(other services could be exploited, locally and/or remotely)

Note : Microsoft recommends (quoted from advisory) that:
If you have not already applied the MS03-007 patch from 
this bulletin, Microsoft recommends you apply the MS03-013 
patch as it also corrects an additional vulnerability.  

Solution : see http://www.microsoft.com/technet/security/bulletin/ms03-007.mspx
or http://www.microsoft.com/technet/security/bulletin/MS03-013.mspx

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q815021";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Trevor Hemsley");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, xp:2, win2k:4) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q811493") > 0 &&
     hotfix_missing(name:"Q815021") > 0 &&
     hotfix_missing(name:"840987") > 0 )
{
 if ( hotfix_check_sp(xp:2) > 0 && hotfix_missing(name:"890859") <= 0 ) exit(0);
	security_hole(get_kb_item("SMB/transport"));
}
