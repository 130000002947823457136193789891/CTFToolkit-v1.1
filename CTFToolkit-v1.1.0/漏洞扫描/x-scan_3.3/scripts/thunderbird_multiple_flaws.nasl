#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14729);
 script_bugtraq_id(11174, 11171, 11170);
 script_version("$Revision: 1.1 $");

 name["english"] = "Mozilla/Thunderbird multiple flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla and/or Thunderbird, an alternative mail user
agent.

The remote version of this software is vulnerable to several flaws which
may allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to send a rogue email
to a victim on the remote host.

Solution : Upgrade to Mozilla 1.7.3 or ThunderBird 0.8
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
  if ( ereg(pattern:"^(0\.|1\.([0-6]\.|7\.[0-2]))", string:moz) ) 
  {
   security_hole(0);
   exit(0);
  }
}


bird = get_kb_item("Mozilla/ThunderBird/Version");
if (bird)
{
  if (ereg(pattern:"0\.[0-7] ", string:bird) )
     security_hole(0);
}
