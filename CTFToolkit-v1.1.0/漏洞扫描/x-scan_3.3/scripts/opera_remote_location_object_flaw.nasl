#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: GreyMagic Software
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14261);
 script_bugtraq_id(10873);
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8331");
 
 script_version("$Revision: 1.4 $");

 name["english"] = "Opera remote location object cross-domain scripting vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Opera - an alternative web browser.

This version contains a flaw that allows a remote 
cross site scripting attack. 

This flaw exists because Opera fails to block write access to the 'location' object.
This could allow a user to create a specially crafted URL to overwrite 
methods within the 'location' object that would execute arbitrary code 
in a user's browser within the trust relationship between the browser and the server, 
leading to a loss of integrity.

Solution : Install Opera 7.54 or newer.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("opera_multiple_flaws.nasl");
 script_require_keys("Host/Windows/Opera/Version");
 exit(0);
}

v = get_kb_item("Host/Windows/Opera/Version");
if(strlen(v))
{
  report = "
We have determined that you are running Opera v." + v + ". 

This version contains a flaw that allows a remote 
cross site scripting attack. 

This flaw exists because Opera fails to block write access to the 'location' object.
This could allow a user to create a specially crafted URL to overwrite 
methods within the 'location' object that would execute arbitrary code 
in a user's browser within the trust relationship between the browser and the server, 
leading to a loss of integrity.

Solution : Upgrade to version 7.54 or newer
Risk factor : High";

  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 54))security_hole(port:port, data:report);
}


