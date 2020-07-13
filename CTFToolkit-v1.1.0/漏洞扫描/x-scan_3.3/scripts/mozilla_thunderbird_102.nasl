#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17605);
 script_cve_id("CAN-2005-0399");
 script_bugtraq_id(12881);
 script_version("$Revision: 1.2 $");

 name["english"] = "Mozilla Thunderbird < 1.0.2";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla Thunderbird, an email client.

The remote version of this software is vulnerable to a heap overflow
vulnerability when it processes GIF images.

An attacker may exploit this flaw to execute arbitrary flaw on the remote
host. To exploit this flaw, an attacker would need to send a malformed
GIF image to a victim on the remote host and wait for him to open it.

Solution : Upgrade to Mozilla ThunderBird 1.0.2
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla Thunderbird";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_firefox_code_exec.nasl");
 exit(0);
}


moz = get_kb_item("Mozilla/ThunderBird/Version");
if ( tb )
{
  if ( ereg(pattern:"^(0\.|1\.0\.[01])", string:tb) )
  {
   security_hole(0);
   exit(0);
  }
}

