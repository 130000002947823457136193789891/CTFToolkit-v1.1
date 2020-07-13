#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if(description)
{
  script_id(11929);
# script_cve_id("CVE-MAP-NOMATCH");
  script_version ("$Revision: 1.8 $");
 
  script_name(english: "SAP DB detection");
 
  desc["english"] = "
SAP/DB vserver is running on this port.

** Please make sure that you applied the last patches, as a 
** buffer overflow attack has been published against it.

Solution : upgrade to version 7.4.03.30 if needed
Risk factor : None / High";

# In fact, the overflow is against niserver (on port 7269)

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect SAP DB vserver";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
  script_family(english:"Service detection");
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports(7210);	# Services/unknown?
  exit(0);
}

include("misc_func.inc");
##include("dump.inc");

port = 7210;
if ( ! get_port_state(port) ) exit(0);


r = hex2raw(s:	"51000000035b00000100000000000000" +
		"000004005100000000023900040b0000" +
		"d03f0000d03f00000040000070000000" +
		"4e455353555320202020202020202020" +
		"0849323335333300097064626d73727600");

s = open_sock_tcp(port);
if ( ! s ) exit(0);
send(socket: s, data: r);

r2 = recv(socket: s, length: 64);

##dump(dtitle: "SAP", ddata: r2);

if (substr(r2, 0, 6) == hex2raw(s: "40000000035c00"))
{
  security_note(port);
  register_service(port: port, proto: "sap_db_vserver");
}


