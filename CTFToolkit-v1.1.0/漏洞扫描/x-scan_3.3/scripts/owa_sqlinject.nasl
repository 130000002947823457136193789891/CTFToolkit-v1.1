#
# This script was written by Michael J. Richardson <michael.richardson@protiviti.com>
# Vulnerability identified by Donnie Werner of Exploitlabs Research Team
#

if(description)
{
  script_id(17636);
  script_version ("$Revision: 1.2 $");
  script_cve_id("CAN-2005-0420");
  script_bugtraq_id(12459);
  name["english"] = "Outlook Web Access URL Injection";

  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running Microsoft Outlook Web Access 2003.

Due to a lack of santization of the user input, the remote version of this software 
is vulnerable to URL injection which can be exploited to redirect a user to a different, 
unauthorized web server after authenticating to OWA.  This unauthorized site could be 
used to capture sensitive information by appearing to be part of the web application.

See also : http://exploitlabs.com/files/advisories/EXPL-A-2005-001-owa.txt
Solution : None at this time
Risk factor : Medium";


 script_description(english:desc["english"]);

 summary["english"] = "The remote host is running Microsoft Outlook Web Access 2003 and is vulnerable to URL Injection.";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2005 Michael J. Richardson",
                francais:"Ce script est Copyright (C) 2005 Michael J. Richardson");

 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))
  exit(0);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

req = http_get(item:string(url, "/exchweb/bin/auth/owalogon.asp?url=http://12345678910"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL ) exit(0);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) &&  
   "owaauth.dll" >< res && 
   '<INPUT type="hidden" name="destination" value="http://12345678910">' >< res)
  {
    security_warning(port);
    exit(0);
  }
