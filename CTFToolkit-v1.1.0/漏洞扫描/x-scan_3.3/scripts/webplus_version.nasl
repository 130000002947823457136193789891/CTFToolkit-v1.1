#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# Changes by rd :
#  - use of function to simplify code
#
# See the Nessus Scripts License for details
#

if(description)
{
 
 script_id(10373);
 script_version ("$Revision: 1.17 $");
 # script_cve_id("CVE-MAP-NOMATCH");

 name["english"] = "TalentSoft Web+ version detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plug-in detects the version of Web+ CGI. The Web+ CGI has a known 
vulnerability that enables a remote attacker to gain access to local files.

This bug is known to exist in Web+ 4.X as of March 1999, and probably exists 
in all previous versions as well.

This test in itself does not verify the vulnerability but rather tries to 
discover the version of Web+ which is installed.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Get the version of Web+ CGI";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2000 SecuriTeam");
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

function extract_version(result, port)
{

    resultrecv = strstr(result, "Version: </b>: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "</b>";

    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "<br><b>Web+ Server Compile Number</b>: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<br>";
    resultrecv = resultrecv - "<b>";
    resultrecv = resultrecv - "</b>";

    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "<br><b>Web+ Client Compile Number</b>: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<br>";
    resultrecv = resultrecv - "<b>";
    resultrecv = resultrecv - "</b>";

    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "<br><b>Operating System</b>: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<br>";
    resultrecv = resultrecv - "<b>";
    resultrecv = resultrecv - "</b>";

    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Web+ Server Version");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Web+ Monitor Server Version");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Web+ Client Version");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Release Date");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "User Name");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    resultrecv = resultrecv - "<i>";
    resultrecv = resultrecv - "</i>";
    resultrecv = resultrecv - "<BR>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Company Name");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    resultrecv = resultrecv - "<i>";
    resultrecv = resultrecv - "</i>";
    resultrecv = resultrecv - "<BR>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Web Server IP Address");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "<B>";
    resultrecv = resultrecv - "</B>";
    resultrecv = resultrecv - "&nbsp;</CENTER>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");

    resultrecv = strstr(result, "Web Server Domain Name");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "</B>";
    resultrecv = resultrecv - "&nbsp;</CENTER>";
    
    banner = banner + resultrecv;
    banner = banner + string("\n");
    
    security_warning(port:port, data:banner);
    return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
req1 = string(dir, "/webplus?about");
req1 = http_get(item:req1, port:port);
req2 = string(dir, "/webplus.exe?about");
req2 = http_get(item:req2, port:port);

result = http_keepalive_send_recv(port:port, data:req1);
if(result == NULL)exit(0);

if("TalentSoft Web+" >< result)
 {
  extract_version(result:result, port:port);
  exit(0);
 }

result = http_keepalive_send_recv(port:port, data:req2);
if("TalentSoft Web" >< result)
 {
  extract_version(result:result, port:port);
  exit(0);
 }
}

