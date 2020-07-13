#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11506);
 script_bugtraq_id(7247);
 script_version("$Revision: 1.5 $");
 script_cve_id("CAN-2003-0168");
 
 
 name["english"] = "Quicktime player buffer overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of the Quicktime player is vulnerable to
a buffer overflow.

To exploit it, an attacker would need a user of this host to
visit a rogue webpage with a malformed link in it. He could
then be able to execute arbitrary code with the rights of the user
visiting the page.
	

Solution : Upgrade to Quicktime Player 6.1
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Quicktime Player";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("quicktime_heap_overflow.nasl");
 script_require_keys("SMB/Quicktime/Version");
 exit(0);
}

version = get_kb_item("SMB/Quicktime/Version");
if(!version)exit(0);

if(version < 0x06100000)security_hole(port);
