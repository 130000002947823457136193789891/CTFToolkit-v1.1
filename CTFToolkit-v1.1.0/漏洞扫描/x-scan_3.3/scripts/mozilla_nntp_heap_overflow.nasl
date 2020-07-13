#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16085);
 script_bugtraq_id(12131,12407);
 script_version("$Revision: 1.2 $");

 name["english"] = "Mozilla Browser Network News Transport Protocol Remote Heap Overflow Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla, an alternative web browser.

The remote version of this software is vulnerable to a heap overflow
vulnerability against its nntp functionnality.

This may allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to set up a rogue news site 
and lure a victim on the remote host into reading news from it.

Solution : Upgrade to Mozilla 1.7.5 or newer
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_firefox_code_exec.nasl");
 exit(0);
}




moz = get_kb_item("Mozilla/Version");
if ( moz )
{
  if ( ereg(pattern:"^(0\.|1\.([0-6]\.|7\.[0-3]))", string:moz) ) 
  {
   security_hole(0);
   exit(0);
  }
}

