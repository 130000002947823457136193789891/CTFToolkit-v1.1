#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14235);
 script_bugtraq_id(10810, 10517);

 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8317"); 

 script_version("$Revision: 1.4 $");

 name["english"] = "Opera web browser URI obfuscation";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Opera - an alternative web browser.

The version installed is vulnerable to a flaw wherein a remote
attacker can obscure the URI, leading the user to believe that
He/She is accessing a trusted resource. 

To exploit them, an attacker would need to set up a rogue web site, then
entice a local user to visit the site.  Successful exploitation would enable
the attacker to execute arbitrary code on this host.

Solution : Install Opera 7.54 or newer

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check version of Opera for URI obfuscation bug";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_require_keys("Host/Windows/Opera/Version");
 script_dependencies("opera_multiple_flaws.nasl");
 exit(0);
}



v = get_kb_item("Host/Windows/Opera/Version");
if(strlen(v))
{
  v2 = split(v, sep:".", keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 53))
	security_hole(port);
}
