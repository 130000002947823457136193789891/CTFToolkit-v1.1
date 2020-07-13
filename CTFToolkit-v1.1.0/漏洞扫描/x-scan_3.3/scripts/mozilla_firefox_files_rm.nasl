#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(15408);
 script_version("$Revision: 1.2 $");
 script_bugtraq_id(11311);

 name["english"] = "Firefox Downloaded Files Removal";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Firefox, an alternative web browser.

The remote version of this software contains a weakness which may allow an
attacker to delete arbitrary files in the user download directory. 
To exploit this flaw, an attacker would need to set up a rogue website
and lure a victim on the remote host into visiting it.

See also : http://www.mozilla.org/press/mozilla-2004-10-01-02.html
Solution : Upgrade to Firefox 0.10.1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Firefox";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_firefox_code_exec.nasl");
 script_require_keys("Mozilla/Firefox/version");

 script_require_ports(139, 445);
 exit(0);
}


version =  get_kb_item("Mozilla/Firefox/Version");
if ( ! version ) exit(0);
if ( ereg(pattern:"^0\.([0-9]\.|10\.0)", string:version) ) 
	security_hole(port);
