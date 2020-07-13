#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(15704);
 script_bugtraq_id(11645);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "WhitSoft Development SlimFTPd Remote Buffer Overflow Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running a vulnerable version of SlimFTPd, a small FTP
server for Windows. It is reported that versions up to 3.15 are prone to buffer
overflow vulnerability which may allow an attacker to execute arbitrary code on
this host. A attacker need a valid FTP account to exploit this flaw.

Solution : Upgrade to SlimFTPd 3.16 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Gets the version of the remote SlimFTPd server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

# Check starts here

include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if ( egrep(pattern:"^220-SlimFTPd ([0-2]\.|3\.1[0-5][^0-9])", string:banner) ) security_hole(port);



