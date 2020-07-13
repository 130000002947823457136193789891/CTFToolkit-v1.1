#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: GreyMagic <http://www.greymagic.com/> and Tom Gilder
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14245);
 script_bugtraq_id(10452);
 
 script_version("$Revision: 1.5 $");

 name["english"] = "Opera web browser address bar spoofing weakness (2)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Opera - an alternative web browser.

This version of Opera is vulnerable to a security weakness 
that may permit malicious web pages to spoof address bar information. 
It is reported that the 'favicon' feature can be used to spoof the domain 
of a malicious web page. An attacker can create an icon that includes the 
text of the desired site and is similar to the way Opera displays information 
in the address bar. 

The attacker can then obfuscate the real address with spaces. 

This issue can be used to spoof information in the address bar, 
page bar and page/window cycler. 


Solution : Install Opera 7.51 or newer.
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
This version is vulnerable to a security weakness 
that may permit malicious web pages to spoof address bar information. 
It is reported that the 'favicon' feature can be used to spoof the domain 
of a malicious web page. An attacker can create an icon that includes the 
text of the desired site and is similar to the way Opera displays information 
in the address bar. 

The attacker can then obfuscate the real address with spaces. 

This issue can be used to spoof information in the address bar, 
page bar and page/window cycler. 


Solution : Upgrade to version 7.51 or newer
Risk factor : High";

  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 51))security_hole(port:port, data:report);
}
