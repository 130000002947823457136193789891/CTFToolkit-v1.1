#
# (C) Noam Rathaus
#
#
if(description)
{
 script_id(11968);
 script_version("$Revision: 1.5 $");
 name["english"] = "DameWare Mini Remote Control Information Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running DameWare Mini Remote Control.
This program allows remote attackers to determine the OS type and
which Service Pack is installed on the server.

Solution: Filter out incoming traffic to this port to minimize the
threat.

Risk Factor: Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "DameWare Mini Remote Control Information Disclosure";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports(6129, "Services/dameware");
 script_dependencies("find_service2.nasl");
 exit(0);
}

# Check starts here
include("dump.inc");
debug = 0;
port = get_kb_item("Services/dameware");
if (! port) port = 6129;


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  rec = recv(socket:soc, length:8192);

  if (debug)
  {
   dump(ddata:rec,dtitle:"DameWare");
  }

  if (!((rec[0] == raw_string(0x30)) && (rec[1] == raw_string(0x11))))
  {
   exit(0);
  }

  rec = insstr(rec, raw_string(0x00), 28, 28);
  rec = insstr(rec, raw_string(0x01), 36, 36);

  send(socket:soc, data:rec);

  rec = recv(socket:soc, length:8192);

  if (debug)
  {
   dump(ddata:rec,dtitle:"DameWare");
  }

  if (!((rec[0] == raw_string(0x10)) && (rec[1] == raw_string(0x27))))
  {
   exit(0);
  }

  windows_version = "";
  if ((rec[16] == raw_string(0x28)) && (rec[17] == raw_string(0x0a)))
  {
   windows_version = "Windows XP";
   if (debug)
   {
    display("Windows XP - ");
   }
  }
  if ((rec[16] == raw_string(0x93)) && (rec[17] == raw_string(0x08)))
  {
   windows_version = "Windows 2000";
   if (debug)
   {
    display("Windows 2000 - ");
   }
  }
  if (windows_version == "")
  {
   exit(0);
  }

  service_pack = "";
  for (i = 24; rec[i] != raw_string(0x00); i = i + 1)
  {
   service_pack = string(service_pack, rec[i]);
  }

  if (debug)
  {
   display(service_pack);
   display("\n");
  }

  report = 
"Using DameWare mini remote control, it was possible to determine that the 
remote host is running ";
  report = string(report, windows_version);
  report = string(report, " - ");
  report = string(report, service_pack);

  security_note(port:port, data:report);
 } 
}
