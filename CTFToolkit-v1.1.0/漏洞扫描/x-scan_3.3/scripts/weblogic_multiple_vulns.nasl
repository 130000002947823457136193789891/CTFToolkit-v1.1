#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14722);
 script_bugtraq_id(11168);
 script_version ("$Revision: 1.1 $");
 
 
 name["english"] = "WebLogic Multiple Vulnerabities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is a version of BEA WebLogic which is older
than version 8.1 SP3.

There are multiple vulnerabilities in the remote version of this server which
may allow unautorized access on the remote host or to get the content of the
remote JSP scripts.

See also : 
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-65.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-66.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-67.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-68.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-69.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-70.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-71.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-72.00.jsp

Solution : Apply Service Pack 3 on WebLogic 8.1
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of WebLogic";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/weblogic");
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);

if ("WebLogic " >!< banner) exit(0);	 # Not WebLogic


if (egrep(pattern:"WebLogic .* ([0-7]\.|8\.(0|1 [^S]|1 SP[0-2]))", string:banner))
{
 security_hole(port);
}
 

