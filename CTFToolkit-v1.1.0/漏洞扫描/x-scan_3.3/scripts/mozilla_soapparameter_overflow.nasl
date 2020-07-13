#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14192);
 script_bugtraq_id(10843);
 script_cve_id("CAN-2004-0722");
 script_version("$Revision: 1.2 $");

 name["english"] = "Mozilla SOAPParameter Integer Overlow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla an alternative web browser.

The remote version of this software is vulnerable to an integer overflow
in the SOAPParameter object constructor. An attacker may exploit this flow
to corrupt the process memory and possibly to execute arbitrary code on
the remote host.

To exploit this flaw, an attacker would need to set up a rogue website 
and lure a victim on the remote host into visiting it.

Solution : Upgrade to Mozilla 1.7.1
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
  if ( moz && ereg(pattern:"^(0\.|1\.([0-6]\.|7\.0))", string:moz) ) 
  {
   security_hole(0);
   exit(0);
  }
}

