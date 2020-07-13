#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17637);
 script_bugtraq_id(12905);
 script_version("$Revision: 1.2 $");
 script_cve_id("CAN-2004-0431");
 
 name["english"] = "Quicktime PictureViewer Buffer Overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using QuickTime, a popular media player/Plug-in
which handles many Media files.

The remote version of this software contains a buffer overflow vulnerability
in its PictureViewer which may allow an attacker to execute arbitrary code
on the remote host.

To exploit this vulnerability, an attacker needs to send a malformed image
file to a victim on the remote host and wait for her to open it using
QuickTime PictureViewer

Solution : Uninstall this software or upgrade to version 6.5.2 (when available)
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of QuickTime Player/Plug-in";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
		   
 exit(0);
}


version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Apple Computer, Inc./Quicktime/Version");
if (version && version <= 0x06528000 ) security_hole(port);
