#TRUSTED 36276caf7362f5976740b1e7c60add01099333f441cb5cdd6861a61f90ca8d54d681cec0f2a328fdd26c310c5be72c773abc2c811dd1b65e991fcc08845181be9de3345c2b54aa00f4380489a73df8e63ff781b6e35dc3e54f519a7d0c561882e0ed6e3d6ad616b9f5057d01103f1da4ae1416820ae64e73adb09e97addc273d2e771f0755efeea2b4e2d386e2c9cc93540490197e89e8746c558cef79d582f330cbdea68dc1a56ea63044a08be9d84f24812679abb959e458eff56666ce762ccbe895cd319a1711daae0f4023d650d7fbc6adf7172d389471cad14bd676e55fdf1b0421f1978b7be8d380da88545470ae2ebe0ab0013d840cba0606a9221f017a0010d41674dd549c3d0765a90c67d5643d755df4840a94663e05b8ae1c19a3514a16e530ffaf92e166659d547ba81310745af346c6b8334bdfa85a23294bea2567436d164d88a8d44e0ec133002c247917716b0f0bd887093c15db46074f69e68434eba5935852fe2120798ab549404bc5ad1d24567af686fd6f70c95670157d5d781946e4f5091ed8206460828677f4b9a859ca8c225b1e483c96d7ecef7b351fcf8fbb5954f5a8f7b893e4b240739f334e92cf2264153a4ac5efdd904afb904a9021dd54e1d1f06b660b8e8834b5c5e92faa1bf562cf41f729c99edc9b48af360a57e3fd32de8731ddf27252dcd015a495dc469b014acbba5094b003dacd
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
if ( ! defined_func("pread") || ! defined_func("fread") ||
     ! defined_func("get_preference") ) exit(0);
if ( ! find_in_path("amap") ) exit(0);


if(description)
{
 script_id(14663);
 script_version ("1.10");
 name["english"] = "amap (NASL wrapper)";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs amap to find open ports and identify applications.
See the section 'plugins options' to configure it

";

 script_description(english:desc["english"]);
 
 summary["english"] = "Performs portscan / RPC scan / application recognition";
 script_summary(english:summary["english"]);
 
 script_category(ACT_SCANNER);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "Port scanners";
 family["francais"] = "Scanners de ports";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencies("ping_host.nasl");

 if (NASL_LEVEL < 2181) exit(0);	# Cannot run

 script_add_preference(name: "File containing machine readable results : ", value: "", type: "file");

 script_add_preference(name:"Mode", type:"radio", value: "Map applications;Just grab banners;Port scan only");
 script_add_preference(name:"Quicker", type:"checkbox", value: "no");
 script_add_preference(name:"UDP scan (disabled in safe_checks)", type:"checkbox", value: "no");
 script_add_preference(name:"SSL (disabled in safe_checks)", type:"checkbox", value: "yes");
 script_add_preference(name:"RPC (disabled in safe_checks)", type:"checkbox", value: "yes");

 script_add_preference(name:"Parallel  tasks", type:"entry", value: "");
 script_add_preference(name:"Connection retries", type:"entry", value: "");
 script_add_preference(name:"Connection timeout", type:"entry", value: "");
 script_add_preference(name:"Read timeout", type:"entry", value: "");

 exit(0);
}

#
function hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);  # remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2) display("hex2raw: odd string: ", s, "\n");
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}

if (NASL_LEVEL < 2181 || ! defined_func("pread") || ! defined_func("get_preference"))
{
  set_kb_item(name: "/tmp/UnableToRun/14663", value: TRUE);
  display("Script #14663 (amap_wrapper) cannot run - upgrade libnasl\n");
  exit(0);
}

function on_exit()
{
  if (tmpnam) unlink(tmpnam);
}

ip = get_host_ip();
esc_ip = ""; l = strlen(ip);
for (i = 0; i < l; i ++) 
  if (ip[i] == '.')
    esc_ip = strcat(esc_ip, "\.");
  else
    esc_ip = strcat(esc_ip, ip[i]);

res = script_get_preference_file_content("File containing machine readable results : ");
if (res)
  res = egrep(pattern: "^" + esc_ip + ":[0-9]+:", string: res);
if (! res)
{
# No result, launch amap
tmpdir = get_tmp_dir();
if ( ! tmpdir ) exit(0);
tmpnam = strcat(tmpdir, "amap-", get_host_ip(), "-", rand());

p = script_get_preference("UDP scan (disabled in safe_checks)");
if ("yes" >< p)
 udp_n = 1;
else
 udp_n = 0;

n_ports = 0;

for (udp_flag = 0; udp_flag <= udp_n; udp_flag ++)
{
 i = 0;
 argv[i++] = "amap";
 argv[i++] = "-q";
 argv[i++] = "-U";
 argv[i++] = "-o";
 argv[i++] = tmpnam;
 argv[i++] = "-m";
 if (udp_flag) argv[i++] = "-u";

 p = script_get_preference("Mode");
 if ("Just grab banners" >< p) argv[i++] = '-B';
 else if ("Port scan only" >< p) argv[i++] = '-P';
 else argv[i++] = '-A';

 # As all UDP probes are declared harmful, -u is incompatible with -H
 # Amap exits immediatly with a strange error.
 # I let it run just in case some "harmless" probes are added in a 
 # future version

 if (safe_checks()) argv[i++] = "-H";

 p = script_get_preference("Quicker");
 if ("yes" >< p) argv[i++] = "-1";

 # SSL and RPC probes are "harmful" and will not run if -H is set

 p = script_get_preference("SSL (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-S";
 p = script_get_preference("RPC (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-R";

 p = script_get_preference("Parallel  tasks"); p = int(p);
 if (p > 0) { argv[i++] = '-c'; argv[i++] = p; }
 p = script_get_preference("Connection retries"); p = int(p);
 if (p > 0) { argv[i++] = '-C'; argv[i++] = p; }
 p = script_get_preference("Connection timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-T'; argv[i++] = p; }
 p = script_get_preference("Read timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-t'; argv[i++] = p; }

 argv[i++] = ip;
 pr = get_preference("port_range");
 if (! pr) pr = "1-65535";
 foreach p (split(pr, sep: ',')) argv[i++] = p;

 res1 = pread(cmd: "amap", argv: argv, cd: 1, nice: 5);
 res += fread(tmpnam);
}

# IP_ADDRESS:PORT:PROTOCOL:PORT_STATUS:SSL:IDENTIFICATION:PRINTABLE_BANNER:FULL_BANNER

 foreach line(split(res))
 {
  v = eregmatch(string: line, pattern: '^'+esc_ip+':([0-9]+):([^:]*):([a-z]+):([^:]*):([^:]*):([^:]*):(.*)$');
  if (! isnull(v) && v[3] == "open")
  {
   scanner_status(current: ++ n_ports, total: 65535 * 2);
   proto = v[2];
   port = int(v[1]); ps = strcat(proto, ':', port);
   scanner_add_port(proto: proto, port: port);
   # As amap sometimes give several results on a same port, we save 
   # the outputs and remember the last one for every port
   # The arrays use a string index to save memory
   amap_ident[ps] = v[5];
   amap_ssl[ps] = v[4];
   amap_print_banner[ps] = v[6];
   amap_full_banner[ps] = v[7];

  }
 }
}

set_kb_item(name: "Host/scanned", value: n_ports != 0);

if (udp_n && n_ports)
  set_kb_item(name: "Host/udp_scanned", value: 1);

scanner_status(current: 65535 * 2, total: 65535 * 2);

function cvtbanner(b)
{
  local_var i, l, x;
  l = strlen(b);

  if (b[0] == '0' && b[1] == 'x')
   return hex2raw(s: substr(b, 2));

  x = "";
  for (i = 0; i < l; i ++)
   if (b[i] != '\\')
    x += b[i];
   else
   {
    i++;
    if (b[i] == 'n') x += '\n';
    else if (b[i] == 'r') x += '\n';
    else if (b[i] == 't') x += '\t';
    else if (b[i] == 'f') x += '\f';
    else if (b[i] == 'v') x += '\v';
    else if (b[i] == '\\') x += '\\';
    else display('cvtbanner: unhandled escape string \\'+b[i]+'\n');
   }
  return x;
}

if (! isnull(amap_ident))
 foreach p (keys(amap_ident))
 {
  v = split(p, sep: ':', keep: 0);
  proto = v[0]; port = int(v[1]);
  if (proto == "tcp")
  {
   soc = open_sock_tcp(port);
   if (soc)
    close(soc);
   else
    security_hole(port: port, data: "Either this port is dynamically allocated
or amap killed this service.
If so, upgrade it!

Risk : None / High\n");
  }
  id = amap_ident[p];
  if (id && id != "unidentified" && id != 'ssl')
  {
   security_note(port: port, proto: proto, data: "Amap has identified this service as " + id);
   set_kb_item(name: "Amap/"+proto+"/"+port+"/Svc", value: id);
  }

  banner = cvtbanner(b: amap_print_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/PrintableBanner", value: banner);

  banner = cvtbanner(b: amap_full_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/FullBanner", value: banner);
 }
