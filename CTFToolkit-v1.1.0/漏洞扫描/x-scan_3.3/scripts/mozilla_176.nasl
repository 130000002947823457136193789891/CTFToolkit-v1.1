#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17604);
 script_bugtraq_id(12659, 12798, 12881, 12884, 12885);
 script_version("$Revision: 1.2 $");

 name["english"] = "Mozilla Browser < 1.7.6";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla, an alternative web browser.

The remote version of this software contains various security issues which may
allow an attacker to impersonate a website and to trick a user into 
accepting and executing arbitrary files or to cause a heap overflow in the
FireFox process and execute arbitrary code on the remote host.

Solution : Upgrade to Mozilla 1.7.6
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_firefox_code_exec.nasl");
 exit(0);
}


moz = get_kb_item("Mozilla/Version");
if ( moz )
{
  if ( moz && ereg(pattern:"^(0\.|1\.([0-6]\.|7\.[0-5]([^0-9]|$)))", string:moz) ) 
  {
   security_hole(0);
   exit(0);
  }
}

