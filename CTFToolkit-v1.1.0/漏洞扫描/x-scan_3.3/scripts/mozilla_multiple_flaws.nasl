#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14728);
 script_bugtraq_id(11194, 11192, 11179, 11177, 11171, 11169 );
 script_version("$Revision: 1.2 $");

 name["english"] = "Mozilla/Firefox multiple flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla and/or Firefox, an alternative web browser.

The remote version of this software is vulnerable to several flaws which
may allow an attacker to execute arbitrary code on the remote host, to
get access to content of the users clipboard or to perform a cross-domain
cross site scripting attack.

To exploit this flaw, an attacker would need to set up a rogue website 
and lure a victim on the remote host into visiting it.

Solution : Upgrade to Mozilla 1.7.3 or Firefox 0.10.0
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


fox = get_kb_item("Mozilla/Firefox/Version");
if (fox)
{
  if (ereg(pattern:"0\.[0-9]\.", string:fox) )
     security_hole(0);
}
