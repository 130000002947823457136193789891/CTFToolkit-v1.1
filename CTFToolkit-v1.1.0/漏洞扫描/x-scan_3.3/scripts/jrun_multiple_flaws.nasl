#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14810);
 script_cve_id("CAN-2004-0646", "CAN-2004-0928", "CAN-2004-1477", "CAN-2004-1478");
 script_bugtraq_id(11245);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Macromedia JRun Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running JRun, a J2EE application server running on top
of IIS or Apache.

There are multiple flaws in the remote version of this software :

 - The JSESSIONID variable is not implemented securely. An attacker may
   use this flaw to guess the session id number of other users ;

 - There is a code disclosure issue which may allow an attacker to obtain
   the contents of a .cfm file by appending ';.cfm' to the file name

 - There is a buffer overflow vulnerability if the server connector is 
   configured in 'verbose' mode. An attacker may exploit this flaw to 
   execute arbitrary code on the remote host.

See also :
	http://www.macromedia.com/devnet/security/security_zone/mpsb04-08.html
	http://www.macromedia.com/devnet/security/security_zone/mpsb04-09.html


Solution : Upgrade to the newest version of this software
Risk factor : High";
	

 script_description(english:desc["english"]);
 
 summary["english"] = "downloads the source of CFM scripts";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "webmirror.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

function check(file)
{
  file = str_replace(find:".cfm", replace:";.cfm", string:file);
  req = http_get(item:file, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( ! r ) exit(0);
  r = tolower(r);
  if ( egrep(pattern:"< *(cfinclude|cfset|cfparam)", string:r) )
	{
  	security_hole(port);
	return(1);
	}
 return(0);
}

port = get_http_port(default:80);
banner = get_http_banner(port:port);

if( banner && "JRun" >< banner )
{
 if(check(file:"/index.cfm"))exit(0);
 files = get_kb_list(string("www/", port, "/content/extensions/cfm"));
 if(isnull(files))exit(0);
 files = make_list(files);
 check(file:files[0]);
}
