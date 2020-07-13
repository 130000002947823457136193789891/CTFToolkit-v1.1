#
# Noam Rathaus noamr@beyondsecurity.com
#
if(description)
{
 script_id(12298);
 script_bugtraq_id(10514);
 script_version("$Revision: 1.6 $");
 name["english"] = "ADODB.Stream object from Internet Explorer (KB870669)";

 script_name(english:name["english"]);

 desc["english"] = "
An ADO stream object represents a file in memory.  The stream object contains 
several methods for reading and writing binary files and text files. 
When this by-design functionality is combined with known security 
vulnerabilities in Microsoft Internet Explorer, an Internet Web site could
execute script from the Local Machine zone.

This behavior occurs because the ADODB.Stream object permits
access to the hard disk when the ADODB.Stream object is hosted
in Internet Explorer.

Solution : http://support.microsoft.com/?kbid=870669
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for KB870669";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

value = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{00000566-0000-0010-8000-00AA006D2EA4}/Compatibility Flags");

if ( value && value != 1024  && hotfix_missing(name:"870669") )
   security_note(port);
