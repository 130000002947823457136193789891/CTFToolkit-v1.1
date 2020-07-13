#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# This script is released under the GNU GPLv2
# Ref: Amit Klein (August 2004)
# Tenable adds
# - check for OWA on port 80


if(description)
{
 script_id(14254);
 script_bugtraq_id(10902);
 script_version("$Revision: 1.6 $");
 script_cve_id("CAN-2004-0203");
 name["english"] = "Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (842436)";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running a version of the Outlook Web Access which contains 
cross site scripting flaws.

This vulnerability could allow an attacker to convince a user 
to run a malicious script. If this malicious script is run, it would execute 
in the security context of the user. 
Attempts to exploit this vulnerability require user interaction. 

This vulnerability could allow an attacker access to any data on the 
Outlook Web Access server that was accessible to the individual user.

It may also be possible to exploit the vulnerability to manipulate Web browser caches
and intermediate proxy server caches, and put spoofed content in those caches.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-026.mspx

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-026 via the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl", "find_service.nes", "http_version.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports("Services/www", 80, 139, 445);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("smb_hotfixes.inc");


# we will first ensure that OWA is running
port = get_http_port(default:80);

if ( ! can_host_asp(port:port) )
        exit(0);

cgi = "/exchange/root.asp";
if(! is_cgi_installed_ka(item:cgi, port:port))
        exit(0);

# display("exchange owa installed\n");

# now check for the patch
if ( hotfix_check_nt_server() <= 0 ) 
	exit(0);

vers = hotfix_check_exchange_installed();
if ( vers == NULL ) 
	exit(0);

if ( hotfix_missing(name:"KB842436") > 0 ) 
	security_warning(get_kb_item("SMB/transport"));


