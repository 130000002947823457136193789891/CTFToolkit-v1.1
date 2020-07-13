#
# This script was written by Michael Scheidell <scheidell at secnap.net>
#
# See the Nessus Scripts License for details
#
#
# Also supercedes MS02-005, MS02-047, MS02-027, MS02-023, MS02-015, MS01-015
#
# 

if(description)
{
 script_id(10861);
 script_bugtraq_id(11388, 11385, 11383, 11381, 11377, 11367, 11366);
 if ( NASL_LEVEL >= 2191 ) script_bugtraq_id(10473, 8565, 9009, 9012, 9013, 9014, 9015, 9182, 9663, 9798, 12477, 12475, 12473, 12530, 13123, 13117, 13120);
 script_version("$Revision: 1.67 $");
 #script_cve_id("CAN-2004-0842", "CAN-2004-0727", "CAN-2004-0216", "CAN-2004-0839", "CAN-2004-0844", "CAN-2004-0843", "CAN-2004-0841", "CAN-2004-0845");
 if ( NASL_LEVEL >= 2191 ) script_cve_id("CAN-2003-0814", "CAN-2003-0815", "CAN-2003-0816", "CAN-2003-0817", "CAN-2003-0823", "CAN-2004-0549", "CAN-2004-0566", "CAN-2003-1048", "CAN-2001-1325", "CAN-2001-0149", "CAN-2001-0727", "CAN-2001-0875", "CVE-2001-1325", "CVE-2001-0149", "CVE-2001-0727", "CVE-2001-0875", "CVE-2001-0339", "CVE-2001-0002", "CAN-2002-0190", "CVE-2002-0026", "CAN-2003-1326", "CVE-2002-0027", "CVE-2002-0022", "CAN-2003-1328", "CAN-2002-1262", "CAN-2002-0193", "CAN-1999-1016", "CVE-2003-0344", "CAN-2003-0233", "CAN-2003-0309", "CAN-2003-0113", "CAN-2003-0114", "CAN-2003-0115", "CAN-2003-0116", "CAN-2003-0531", "CAN-2003-0809", "CAN-2003-0530", "CAN-2003-1025", "CAN-2003-1026", "CAN-2003-1027", "CAN-2005-0554", "CAN-2005-0555");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0014");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0016");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-A-0006");
 name["english"] = "IE 5.01 5.5 6.0 Cumulative patch (890923)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The July 2004 Cumulative Patch for IE is not applied on the remote host.

Impact of vulnerability: Run code of attacker's choice. 

Recommendation: Customers using IE should install the patch immediately. 

See http://www.microsoft.com/technet/security/bulletin/ms05-020.mspx
Risk factor : High";

 script_description(english:desc["english"]); 
 summary["english"] = "Determines whether the hotfix 890923 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}


include("smb_hotfixes.inc");

# 883939 superseedes MS05-020
if ( hotfix_missing(name:"883939.*") == 0 &&
     "883939" >!<  get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion") ) exit(0); 

if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

version = get_kb_item("SMB/WindowsVersion");
if(version)
{
 value = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/Version");
 if ( value )
  {
   minorversion = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion");
   report = string("The remote host is running IE Version ",value);
   if(minorversion)
   {
    if ( hotfix_missing(name:"890923.*") == 0 ) exit(0); 
    if ( "890923" >!< minorversion ) missing = "890923 (MS05-020)";
   }
   else if ( hotfix_missing(name:"890923.*") > 0 ) 
     missing = "890923 (MS05-020)";
   else exit(0);

   report += '\nHowever is it missing Microsoft Hotfix ' + missing + '\n';
   report += 'Solution : http://www.microsoft.com/technet/security/bulletin/ms05-020.mspx\nRisk Factor : High\n';

   if( missing ) security_hole(port:get_kb_item("SMB/transport"), data:report);
  }
}
