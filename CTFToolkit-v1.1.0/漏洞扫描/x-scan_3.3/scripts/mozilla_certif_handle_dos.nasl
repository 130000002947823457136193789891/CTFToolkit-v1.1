#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Marcel Boesch <marboesc@student.ethz.ch>.
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14668);
 script_bugtraq_id(10703);
 script_cve_id("CAN-2004-0758");
 script_version("$Revision: 1.2 $");

 name["english"] = "Mozilla/Firefox security manager certificate handling DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla, an alternative web browser.

The Mozilla Personal Security Manager (PSM) contains  a flaw
that may permit a attacker to import silently a certificate into
the PSM certificate store.
This corruption may result in a deny of SSL connections.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla/Firefox";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_firefox_code_exec.nasl");
 exit(0);
}




moz = get_kb_item("Mozilla/Version");
if ( moz )
{
  if ( moz && ereg(pattern:"^(0\.|1\.([0-6]\.|7\.0|7\.1))", string:moz) ) 
  {
   security_warning(0);
   exit(0);
  }
}


fox = get_kb_item("Mozilla/Firefox/Version");
if (fox)
{
  if (ereg(pattern:"0\.([0-8]\.|9\.[012][^0-9])", string:fox) )
     security_warning(0);
}
