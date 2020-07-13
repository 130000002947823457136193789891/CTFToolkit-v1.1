#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Alexander Antipov <Antipov SecurityLab ru>
#
#  This script is released under the GNU GPL v2
#

if(description) 
{ 
  script_id(15425); 
  script_cve_id("CAN-2004-1578");
  script_bugtraq_id(11332);
  script_version("$Revision: 1.4 $"); 
      
  name["english"] = "Invision Power Board XSS"; 
        
  script_name(english:name["english"]); 

desc["english"] = "
The remote host is running Invision Power Board, a web-based bulletin-board
system written in PHP.

This version of Invision Power Board is vulnerable to cross-site scripting 
attacks, which may allow an attacker to steal users cookies.
        
Solution: Upgrade to the latest version of this software
Risk factor : Medium"; 
        
  script_description(english:desc["english"]); 
        
  summary["english"] = "Checks for Invision Power Board XSS";
  script_summary(english:summary["english"]);
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
	
  script_dependencie("http_version.nasl", "invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if ( ! port || ! get_port_state(port) ) exit(0);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/invision_power_board"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];

    s = string( "GET ", dir, "/index.php?s=5875d919a790a7c429c955e4d65b5d54&act=Login&CODE=00 HTTP/1.1\r\n", "Host: ", get_host_name(), "\r\n", "Referer: <script>foo</script>", "\r\n\r\n");
    soc =  http_open_socket(port);
    if(!soc) exit(0);

    send(socket: soc, data: s);
    r = http_recv(socket: soc);
    http_close_socket(soc);

    if (egrep(pattern:"input type=.*name=.referer.*<script>foo</script>", string:r) )
    { 
      security_warning(port);
    }
  }
}
