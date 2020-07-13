#TRUSTED 09d97b7737e76de3efef5acf48f6259ce67b82ff21d6f40129e92e12e979e7c5f18110c29d41ae4752437f7385f162972b1db05f4d9535b9f6a7a1584a7656baec9ee65cec2d4dd81940f98ec060db5977ce7dcc8ffd774be345f4711c26cc13899149168bd643b90d36e15681a19263c97f36e5f85889626dab70fbfdcfaca59313237d3fb94e3c54e8a2029b8e139ff8deeadef5ad0edb5310ffc11928dcc82ca6e1b9536435318fbeee8b799a3b891a19608a65f851423fbf102cd23b3b4e49e2bc21079a7eb44fc72c3a8136f8a910ee524e85350a95c3e800b68d0e97f7b85e231cb3715490570c1939bc84544e4264be6f5c3043d1308bc8520eeb2b686879fde109b3122c75d9310438022206d7a3eaf4ec41037b2ecc9a9d0c5c3539804cb4a0e17718181c645933ad00295282e20f90d45754d5ec6bc86dc8f20b5c40715537b9eac29ad0bf902c3743851562a69d7f72c6765dcf40a5032f234b0b9e89530644b19f8c060842c69e5678223eb048c79e1b47d8eacf76183ffe73e746e92e19fff81758004737456bb3f98e3cde00d3724b4961da4cdcbaa17e536c77ce1c3dc119f12e79b4f695edf3db3fb6dcaa9ad36451fbfb79e19ca14fc6bec753dd5ad9475924076bfb7baa62fdb39dca5c5a5e929e5c6f9ab14af94212e525537cc0d4c3138d7d2547cefa26a725523f28404857815f552c9374008e05ab
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if ( ! defined_func("pread")) exit(0);
if ( ! find_in_path("nikto.pl") ) exit(0);


if(description)
{
 script_id(14260);
 script_version ("1.5");
 name["english"] = "Nikto (NASL wrapper)";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs nikto(1) to find CGI.
See the section 'plugins options' to configure it

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Find CGI with Nikto";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencies("find_service.nes", "httpver.nasl", "logins.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

# script_add_preference(name:"Force scan all possible CGI directories",
#                       type:"checkbox", value:"no");
 script_add_preference(name:"Force full (generic) scan", 
                      type:"checkbox", value:"no");
 exit(0);
}

#

if (! defined_func("pread"))
{
  set_kb_item(name: "/tmp/UnableToRun/14254", value: TRUE);
  display("Script #14254 (nikto_wrapper) cannot run\n");
  exit(0);
}

user = get_kb_item("http/login");
pass = get_kb_item("http/login");
ids = get_kb_item("/Settings/Whisker/NIDS");

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0);

# Nikto will generate many false positives if the web server is broken
no404 = get_kb_item("www/no404/" + port);
if (no404 || no404 !~ '^[ \t\n\r]*$') exit(0);

i = 0;
argv[i++] = "nikto.pl";

httpver = get_kb_item("http/"+port);
if (httpver == "11")
{
  argv[i++] = "-vhost";
  argv[i++] = get_host_name();
}

argv[i++] = "-h"; argv[i++] = get_host_ip();
argv[i++] = "-p"; argv[i++] = port;

encaps = get_port_transport(port);
if (encaps > 1) argv[i++] = "-ssl";

#p = script_get_preference("Force scan all possible CGI directories");
#if ("yes" >< p) argv[i++] = "-allcgi";
p = script_get_preference("Force full (generic) scan");
if ("yes" >< p) argv[i++] = "-gener";

if (idx && idx != "X")
{
  argv[i++] = "-evasion";
  argv[i++] = ids[0];
}

if (user)
{
  if (pass)
    s = strcat(user, ':', pass);
  else
    s = user;
  argv[i++] = "-id";
  argv[i++] = s;
}

r = pread(cmd: "nikto.pl", argv: argv, cd: 1);
if (! r) exit(0);	# error

report = 'Here is the Nikto report:\n';
foreach l (split(r))
{
  display(j ++, "\n");
  l = ereg_replace(string: l, pattern: '^[ \t]+', replace: '');
  if (l[0] == '+' || l[0] == '-' || ! match(pattern: "ERROR*", string: l))
    report += l;
}

security_note(port: port, data: report);
