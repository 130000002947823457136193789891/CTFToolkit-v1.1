#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18488);
 script_bugtraq_id(13952);
 script_version("$Revision: 1.2 $");
 script_cve_id("CAN-2005-0563");
 name["english"] = "Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (895179)";

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

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-029.mspx
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms05-029 via the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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

version = get_kb_item ("SMB/Exchange/Version");

if (version == 55)
{
 if ( hotfix_missing(name:"895179") > 0 ) 
	security_warning(get_kb_item("SMB/transport"));
}
