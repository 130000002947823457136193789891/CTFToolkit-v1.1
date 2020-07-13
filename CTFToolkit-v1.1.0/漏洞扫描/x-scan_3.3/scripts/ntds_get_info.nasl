#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# changes by rd: minor wording in the description
#
#
if (description)
{
 script_id(12105);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "Use LDAP search request to retrieve information from NT Directory Services";

 script_name(english:name["english"]);
 desc["english"] = "
The directory base of the remote server is set to NULL. This allows information 
to be enumerated without any prior knowledge of the directory structure.

Solution : If pre-Windows 2000 compatibility is not required, remove 
pre-Windows 2000 compatibility as follows :

	- start cmd.exe
	- execute the command :
	 net localgroup  'Pre-Windows 2000 Compatible Access' everyone /delete
	- restart the remote host

Risk factor: Medium";

 script_description(english:desc["english"]);
 summary["english"] = "Use LDAP search request to retrieve information from NT Directory Services";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 David Kyger");
 script_family(english:"Remote file access");
 script_require_ports(389);
 exit(0);
}
#
# The script code starts here
#
warning = string("
The server's directory base is set to NULL. This allows information to be enumerated
without any prior knowledge of the directory structure.

The following information was pulled from the server via a LDAP request:\n");

include("misc_func.inc");

port = 389;
if ( ! get_port_state(port) ) exit(0);

senddata = raw_string(
0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04, 0x00, 0x0a, 
0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 
0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 
0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x00
			);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:senddata);
buf = recv(socket:soc, length:4096);
close(soc);
version = string(buf);

if (buf == NULL) exit(0);
	if ("NTDS" >< buf) {
		hbuf = hexstr(buf);
		ntdsinfo = strstr(hbuf, "4e54445320");
		ntdsinfo = ntdsinfo - strstr(ntdsinfo, "308400");
		ntdsinfo = hex2raw(s:ntdsinfo);
		warning  = warning + string(ntdsinfo,"\n\n");
		warning += string("Solution: If pre-Windows 2000 compatibility is not required, remove pre-Windows 2000 compatibility as follows:", "\n", "net localgroup  'Pre-Windows 2000 Compatible Access' everyone /delete", "\n\n");
		warning += string("Risk Factor: Medium","\n");
		security_warning(port:port, data:warning);
	}

