#
# (C) Tenable Network Security
# 

if(description)
{
 script_id(15823);
 script_bugtraq_id(11736);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Alt-N MDaemon Local Privilege Escalation Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Alt-N MDaemon, a SMTP/IMAP server for the Windows 
operating system family. 

It is reported that versions up to and including 7.2.0 are prone to local 
privilege escalation vulnerability.

An local attacker may increase his privilege and execute code with SYSTEM
privileges.

Solution : Upgrade to MDaemon 7.2.1 or newer
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote version of Mdaemon";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SMTP problems";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#


include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_smtp_banner(port:port);
if ( ! banner ) exit(0);

if ( egrep(pattern:"^220.*ESMTP MDaemon ([0-6]\.*|7\.([0-1]\..*|2\.0.*))", string:banner) ) security_warning(port);
