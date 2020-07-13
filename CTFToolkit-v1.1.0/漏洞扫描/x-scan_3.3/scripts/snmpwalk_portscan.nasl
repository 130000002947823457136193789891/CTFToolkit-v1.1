#TRUSTED 2c644d9ab75e273c7c03d2067f284e00c68a271261dd61fe85e6f1f98a24bd09a7b7a9d8a472bde61f5f9f72d570fa1e107abab41b8b526ec4a792205ec4de3aa5e575fac9f263e3686f1b5fca789d971ae49f354ddc29c73a0adad66fd8fc9305ce4f9ec9a22169de326bc3e593e35646e820d93bc8046cb6fd7d2d3010fe665258e911a3998e8ef811a2be7261f9bdc4f5094c88e73f510c552aa1a16a0e6a359673277b6f5750008f338dab52d1ee07e4a318ce71e66e3af9a70b742bff400309295d710fd04900d01aaf597b2a7ab9bedbabac2913acfca88f6f771aa0c6495a1becd013fd6864315ccb3b64d2f6be0d0fff1c16463167bd0351303667faf0d5d9c71b03bd597c53861d81e92b349aa4554c97385e59c65580076221deab2174ba663a1102f11ad2f6a5b49a4dd07885aeb154775983416f425edc70ed4398b43f039937c11f0863149f61247ccc35351814b88a4b1f344b5526f622f89945f9314180bf5dcee90fa356d2122ea207e85d73f4fd738f44b4b630f044d3f8ccf642199b6055497f138e163354137bdb2c4e5d94b746fd83877aca2bc512679347e805bf6740c818ab3aa502d08fa12c719ca66f6d80453f251f30f2f37aa125533c72548a26bfc37c17dd31710d4338bfd34b73b28d4253969210219f696e9ea0fbcd31923f3277526c93767dc85d80da5ac46d7822830c161cc32105377c
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if ( ! defined_func("pread") ) exit(0);
if ( ! find_in_path("snmpwalk") ) exit(0);


if(description)
{
 script_id(14274);
 script_version ("1.5");
 name["english"] = "snmpwalk 'scanner'";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs snmpwalk against the remote machine to find open ports.
See the section 'plugins options' to configure it

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Find open ports with snmpwalk";
 script_summary(english:summary["english"]);
 
 script_category(ACT_SCANNER);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "Port scanners";
 family["francais"] = "Scanners de ports";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencies("ping_host.nasl");

if (NASL_LEVEL < 2181) exit(0);	# Cannot run

 script_add_preference(name: "Community name :", type: "entry", value: "public");
 script_add_preference(name: "SNMP protocol :", type: "radio", value: "1;2c");
 script_add_preference(name: "SNMP transport layer :", type: "radio", value: "udp;tcp");
 script_add_preference(name: "TCP/UDP port :", type: "entry", value: "");
 script_add_preference(name: "Number of retries :", type: "entry", value: "");
 script_add_preference(name: "Timeout between retries :", type: "entry", value: "");
 exit(0);
}

#

if (NASL_LEVEL < 2181) exit(0);	# Cannot run

check = 
 (! safe_checks()) ||
 ("yes" >< get_kb_item("global_settings/experimental_scripts_tests")) ||
 ("yes" >< get_preference("unscanned_closed")) ||
 ("yes" >< get_kb_item("global_settings/thorough_tests"));
# ("Avoid false alarms" >< get_kb_item("global_settings/report_paranoia"))

global_var	snmp_layer, argv, snmp_port, snmp_comm;
seen_tcp_ports = make_list(0);	# Do not want to see this!
seen_udp_ports = make_list(0);	# Do not want to see this!

function make_argv(obj)
{
 local_var	i, p;

 i = 0;
 argv = NULL;
 argv[i++] = "snmpwalk";

 p = script_get_preference("SNMP protocol :");
 if (! p) p = "2c";
 argv[i++] = "-v";
 argv[i++] = p;

 snmp_layer = "udp";

 if (! v506)
 {
  p = script_get_preference("SNMP transport layer :");
  if (p)
  {
   argv[i++] = "-T";
   argv[i++] = p;
   snmp_layer = p;
  }
 }

 p = script_get_preference("Number of retries :");
 if (p && p =~ '^[0-9]+$')
 {
  argv[i++] = "-r";
  argv[i++] = p;
 }

 p = script_get_preference("Timeout between retries :");
 if (p && p =~ '^[0-9]+$')
 {
  argv[i++] = "-t";
  argv[i++] = p;
 }

 p = script_get_preference("TCP/UDP port :");
 if (p && p =~ '^[0-9]+$')
 {
  argv[i++] = "-p";
  argv[i++] = p;
  snmp_port = p;
 }

 if (!v506) argv[i++] = ip;

 p = script_get_preference("Community name :");
 if (strlen(p) == 0) p = "public";
 if (v506) argv[i++] = "-c";
 argv[i++] = p;
 snmp_comm = p;

 # Version 5.0.6 orlater: put the hostname *after* the options
 if (v506) argv[i++] = ip;

 argv[i++] = obj;
}


ver = pread(cmd: "snmpwalk", argv: make_list("snmpwalk", "-V"));
if (ereg(string: ver, pattern: "NET-SNMP version: +([6-9]\.|5\.([1-9]|0\.[6-9]))", icase: 1, multiline: 1))
  v506 = 1;
else
  v506 = 0;

ip = get_host_ip();

i = 0;
scanned = 0; udp_scanned = 0;
foreach o (
  make_list("tcp.tcpConnTable.tcpConnEntry.tcpConnLocalPort.0.0.0.0",
            "tcp.tcpConnTable.tcpConnEntry.tcpConnLocalPort." + ip,
            "udp.udpTable.udpEntry.udpLocalPort.0.0.0.0", 
            "udp.udpTable.udpEntry.udpLocalPort." + ip))
{
 scanner_status(current: 0, total: i++);
 make_argv(obj: o);
 buf = pread(cmd: "snmpwalk", argv: argv);
 proto = substr(o, 0, 2);
 if (buf)
 {
  foreach line( split(buf))
  {
   v = eregmatch(pattern: '=[ \t]*([a-zA-Z0-9-]+:)?[ \t]*([0-9]+)[ \t\r\n]*$',
		string: line);
   if (! isnull(v))
   {
    port = v[2];
    if (proto == 'tcp' && ! seen_tcp_ports[port])
    {
     if (check && proto == "tcp")
     {
      soc = open_sock_tcp(port);
      if (soc)
      {
       scanner_add_port(proto: proto, port: port);
       close(soc);
      }
      else
       display("snmpwalk_portscan(", get_host_ip(), "): TCP port ",  port, " is closed in fact\n");
     }
     else
      scanner_add_port(proto: proto, port: port);
     seen_tcp_ports[port] ++;
    scanned ++;
    }
    if (proto == "udp" && ! seen_udp_ports[port])
    {
     scanner_add_port(proto: proto, port: port);
     seen_udp_ports[port] ++;
     udp_scanned ++;
    }
   }
  }
 } 
}

if (scanned)
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 security_note(port: snmp_port, proto: snmp_layer, 
data: strcat("snmpwalk could get the open port list with the community name ", snmp_comm));
}

if (udp_scanned) set_kb_item(name: "Host/udp_scanned", value: TRUE);

exit(0);

# make_argv(obj: "host.hrSWInstalled.hrSWInstalledTable.hrSWInstalledEntry.hrSWInstalledName");

