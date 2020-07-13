# this code was the "40x_cross_site.nasl" written by SecuriTeam and was modified
# by CIRT.net (sq@cirt.net) (with help from SecuriTeam) to check for multiple cross
# site scripting vuls.
# Update by Felix Huber - huberfelix@webtopia.de - 14.11.2001
# Update by Chris Sullo - sq@cirt.net - 16.11.2001
# false positive fix by Andrew Hintz - http://guh.nu - 1.3.2002
# Update by rd: thanks to Andrew's remarks, HTTP headers are discared
# Update by Chris Sullo - sq@cirt.net - 06/27/2002 -- added .cfm test
#



if (description)
{
 script_id(10815);
 script_bugtraq_id(5305, 7344, 7353, 8037, 9245);
 script_cve_id("CVE-2002-1060");
 script_version("$Revision: 1.34 $");
 script_name(english:"Web Server Cross Site Scripting");
 desc["english"] = "
The remote web server seems to be vulnerable to the Cross Site Scripting 
vulnerability (XSS). The vulnerability is caused by the result returned to 
the user when a non-existing file is requested (e.g. the result contains 
the JavaScript provided in the request).

The vulnerability would allow an attacker to make the server present the 
user with the attacker's JavaScript/HTML code.
Since the content is presented by the server, the user will give it the trust
level of the server (for example, the trust level of banks, shopping centers, 
etc. would usually be high).

Risk factor : Medium

Solutions:

. Allaire/Macromedia Jrun:
      - http://www.macromedia.com/software/jrun/download/update/
      - http://www.securiteam.com/windowsntfocus/Allaire_fixes_Cross-Site_Scripting_security_vulnerability.html
. Microsoft IIS:
      - http://www.securiteam.com/windowsntfocus/IIS_Cross-Site_scripting_vulnerability__Patch_available_.html
. Apache:
      - http://httpd.apache.org/info/css-security/
. ColdFusion:
      - http://www.macromedia.com/v1/handlers/index.cfm?ID=23047
. General:
      - http://www.securiteam.com/exploits/Security_concerns_when_developing_a_dynamically_generated_web_site.html
      - http://www.cert.org/advisories/CA-2000-02.html";
 script_description(english:desc["english"]);
 script_summary(english:"Determine if the remote host is vulnerable to Cross Site Scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.", francais:"Divers");
 script_copyright(english:"(c) 2001 SecuriTeam, modified by Chris Sullo and Andrew Hintz");
 script_dependencie("find_service.nes", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

post[0] = ".jsp";
post[1] = ".shtml";
post[2] = ".thtml";
post[3] = ".cfm";
post[4] = ".php";
post[5] = "";
post[6] = "";
post[7] = "";
post[8] = "";
post[9] = "";
post[10] = "";



dir[0] = ".jsp";
dir[1] = ".shtml";
dir[2] = ".thtml";
dir[3] = ".cfm";
dir[4] = ".php";
dir[5] = "MAGIC";
dir[6] = ".jsp";
dir[7] = ".shtml";
dir[8] = ".thtml";
dir[9] = ".cfm";
dir[10] = ".php";

if(get_port_state(port))
{
 confirmtext = string("<SCRIPT>foo</SCRIPT>");
 for (i = 0; dir[i] ; i = i + 1)
 {
    if ( dir[i] == "MAGIC" )
	url = string("/", confirmtext);
    else
        url = string("/foo" , dir[i] , "?param=", confirmtext, post[i]);


    req = http_get(item:url, port:port);
    r   = http_keepalive_send_recv(port:port, data:req);
    if(confirmtext >< r)
      {
       exploit_url = string("http://", get_host_name(), ":", port, url);
       report = "
 The remote web server seems to be vulnerable to the Cross Site Scripting vulnerability (XSS). The vulnerability is caused
by the result returned to the user when a non-existing file is requested (e.g. the result contains the JavaScript provided
in the request).
The vulnerability would allow an attacker to make the server present the user with the attacker's JavaScript/HTML code.
Since the content is presented by the server, the user will give it the trust
level of the server (for example, the trust level of banks, shopping centers, etc. would usually be high).

Sample url : " + exploit_url + "

Risk factor : Medium

Solutions: ";


 banner = get_http_banner(port:port);
	
 if ( "Allaire" >< banner || "JRun" )
	{
 	solution ++;	
	report += "
. Allaire/Macromedia Jrun:
      - http://www.macromedia.com/software/jrun/download/update/
      - http://www.securiteam.com/windowsntfocus/Allaire_fixes_Cross-Site_Scripting_security_vulnerability.html";
	}
 if ( "Microsoft/IIS" >< banner )
	{
	solution ++;
	report += "
. Microsoft IIS:
      - http://www.securiteam.com/windowsntfocus/IIS_Cross-Site_scripting_vulnerability__Patch_available_.html";
	}

 if ( "Apache" >< banner )
	{
	solution ++;
	report += "
. Apache:
      - http://httpd.apache.org/info/css-security/";
	}

 if ("ColdFusion" >< banner )
	{
	solution ++;
	report += "
. ColdFusion:
      - http://www.macromedia.com/v1/handlers/index.cfm?ID=23047";
	}


 if ( solution == 0 )
	{
	report += "
. General:
      - http://www.securiteam.com/exploits/Security_concerns_when_developing_a_dynamically_generated_web_site.html
      - http://www.cert.org/advisories/CA-2000-02.html";
	}
     
       security_warning(port:port, data:report);
       set_kb_item(name:string("www/", port, "/generic_xss"), value:TRUE);
       exit(0);
      }
 }
}

