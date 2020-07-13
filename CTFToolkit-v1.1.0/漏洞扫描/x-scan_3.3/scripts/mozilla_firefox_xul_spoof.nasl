#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  based on work from
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14181);
 script_bugtraq_id(10796, 10832);
 script_cve_id("CAN-2004-0763");
 script_version("$Revision: 1.6 $");

 name["english"] = "Mozilla/Firefox user interface spoofing";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Mozilla and/or Firefox, an alternative web browser.
This web browser supports the XUL (XML User Interface Language), a language
designed to manipulate the user interface of the browser itself.

Since XUL gives the full control of the browser GUI to the visited websites,
an attacker may use it to spoof a third party website and therefore pretend
that the URL and Certificates of the website are legitimate.

In addition to this, the remote version of this browser is vulnerable to a
flaw which may allow a malicious web site to spoof security properties
such as SSL certificates and URIs.

See also : http://www.nd.edu/~jsmith30/xul/test/spoof.html
Solution : None at this time
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
