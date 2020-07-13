#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17633);
 script_bugtraq_id(12899, 12922);
 script_version ("$Revision: 1.3 $");

 
 name["english"] = "Smail-3 Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of S-mail, a mail transport agent,
which is older or as old as than version 3.2.0.120

The remote version of this software contains various vulnerabilities which
may allow a remote attacker to execute arbitrary code on the remote host
by exploiting a heap overflow in the function which processes the 'MAIL FROM'
command.

To exploit this flaw, an attacker would need to connect on this port and
send a malformed argument to the 'MAIL FROM' command.

Solution : Upgrade to Smail-3.2.0.121 or newer (when available)
Risk factor : High";

 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Checks the version of the remote Smail daemon";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpscan.nasl");
 
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include('smtp_func.inc');
port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_smtp_banner(port:port);
if ( ! banner )exit(0);
if ( ereg(pattern:".* Smail(-)?3\.([01]\.|2\.0\.([0-9] |[0-9][0-9] |1[01][0-9] |120 ))", string:banner) ) security_hole(port);

