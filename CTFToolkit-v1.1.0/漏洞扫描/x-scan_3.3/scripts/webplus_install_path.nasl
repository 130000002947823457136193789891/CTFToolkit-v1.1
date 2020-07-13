#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(12074);
  script_version ("$Revision: 1.3 $");

 name["english"] = "Talentsoft Web+ reveals install path";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running Web+ Application Server.
This service  will reveal the physical path of the application when it receives a 
script file error.

Example: http://<host>/cgi-bin/webplus.exe?script=
Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for Webplus install path disclosure";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 David Kyger");
 family["english"] = "CGI abuses";
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

warning = string("
The remote host is running the TalentSoft Web+ Application Server.
This service is revealing the physical path of the application when it receives a script file error.

The webplus install path follows :");

url = "/cgi-bin/webplus.exe?script=";

port = get_http_port(default:80);


if(get_port_state(port))
 {
  soc = http_open_socket(port);
  if (soc)
  {
    req = http_get(item:url, port:port);
    send(socket:soc, data:req);
    buf = http_recv(socket:soc);
    http_close_socket(soc);
    if ("Web+ Error Message" >< buf)
    {
    path = strstr(buf, " '");
    path = ereg_replace(pattern:" and.*$", replace:"",string:path);
    warning = warning + string("\n", path) + "

Solution : Apply the vendor supplied patch and specify a redirect URL.
See Also: http://www.talentsoft.com/Issues/IssueDetail.wml?ID=WP197
Risk factor : Low";
     security_warning(port:port, data:warning);
    }
  }
 }

