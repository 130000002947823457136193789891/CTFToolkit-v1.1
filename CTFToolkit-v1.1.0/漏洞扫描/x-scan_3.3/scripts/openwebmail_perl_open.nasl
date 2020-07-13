#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18190);
  script_version("$Revision: 1.2 $");
  script_bugtraq_id(13472);

  name["english"] = "Open WebMail Arbitrary Execution Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the version of Open WebMail installed on the
remote host may allow execution of arbitrary shell commands due to its
failure to ensure shell escape characters are removed from filenames
and other strings before trying to read from them. 

Solution : Upgrade to Open WebMail 2.5.1-20050430 or later.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for arbitrary execution vulnerability in Open WebMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/openwebmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: intermediate releases of 2.51 below 20050430 are vulnerable,
  #     as are 2.50 and earlier releases.
  if (ver =~ "^(1\.|2\.([0-4]|50|51$|51 20050([0-3]|4[12])))")
    security_hole(port);
}

