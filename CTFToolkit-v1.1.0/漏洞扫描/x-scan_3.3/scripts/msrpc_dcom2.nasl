#
# (C) Tenable Network Security
#
# v1.2: use the same requests as MS checktool
# v1.16: use one of eEye's request when a null session can't be established
#
if(description)
{
 script_id(11835);
 script_bugtraq_id(8458, 8460);
 script_cve_id("CAN-2003-0715", "CAN-2003-0528", "CAN-2003-0605");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0012");


 script_version ("$Revision: 1.38 $");
 
 name["english"] = "Microsoft RPC Interface Buffer Overrun (KB824146)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Windows which has a flaw in 
its RPC interface, which may allow an attacker to execute arbitrary code 
and gain SYSTEM privileges. 

An attacker or a worm could use it to gain the control of this host.

Note that this is NOT the same bug as the one described in MS03-026 
which fixes the flaw exploited by the 'MSBlast' (or LoveSan) worm.
 
Solution: see http://www.microsoft.com/technet/security/bulletin/MS03-039.mspx 
Risk factor : High";
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if the remote host has a patched RPC interface (KB824146)";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_require_ports("Services/msrpc", 135, 139, 445, 593);
 script_dependencies("smb_nativelanman.nasl"); #KK Liu 10/01/2004
 exit(0);
}

#
# The script code starts here
#

include("smb_func.inc");



function get_smb_host_name()
{
 local_var r, soc, uid, port;

 port = kb_smb_transport();

 if(!get_port_state(port))return NULL;
 soc = open_sock_tcp(port);
 if(!soc)return NULL;

 session_init(socket:soc, hostname:"*SMBSERVER");
 r = NetUseAdd(login:"", password:"", domain:"", share:"IPC$");
 if ( r != 1 ) 
  return NULL;

 r = NetWkstaGetInfo(level:100);
 if ( r == NULL )
  return NULL;
 
 NetUseDel();
 return r[1];
}


 





function dcom_recv(socket)
{
 local_var buf, len;
 
 buf = recv(socket:socket, length:10);
 if(strlen(buf) != 10)return NULL;
 
 len = ord(buf[8]);
 len += ord(buf[9])*256;
 buf += recv(socket:socket, length:len - 10);
 return buf;
}
 

#-------------------------------------------------------------#

function check(req)
{ 
 local_var soc, bindstr, error_code, r;
 
 
 soc = open_sock_tcp(port);
 if(!soc)raisewarn(text:"check: open_sock");

 bindstr = "05000b03100000004800000001000000d016d016000000000100000000000100a001000000000000c00000000000004600000000045d888aeb1cc9119fe808002b10486002000000";
 send(socket:soc, data:hex2raw(s:bindstr));
 r = dcom_recv(socket:soc);
 if(!r)raisewarn(text:"check: dcom_recv");

 send(socket:soc, data:req);
 r = dcom_recv(socket:soc);
 if(!r)return NULL;

 close(soc);
 error_code = substr(r, strlen(r) - 4, strlen(r) - 1);

 return error_code;
}

function check2(req)
{ 
 local_var soc,bindstr, error_code, r;
 
 
 soc = open_sock_tcp(port);
 if(!soc)raisewarn(text:"check2: open_sock");

 bindstr = "05000b03100000004800000001000000d016d016000000000100000000000100a001000000000000c00000000000004600000000045d888aeb1cc9119fe808002b10486002000000";
 send(socket:soc, data:hex2raw(s:bindstr));
 r = dcom_recv(socket:soc);
 if(!r)raisewarn(text:"check2: dcom_recv");

 send(socket:soc, data:req);
 r = dcom_recv(socket:soc);
 close(soc);
 if(!r)return NULL;


 error_code = substr(r, strlen(r) - 8, strlen(r) - 5);
 return error_code;
}


function check3(req)
{
 local_var soc,bindstr, error_code, r;
 
 
 soc = open_sock_tcp(port);
 if(!soc)raisewarn(text:"check3: open_sock");

 bindstr = "05000b03100000004800000002000000d016d016000000000100000001000100b84a9f4d1c7dcf11861e0020af6e7c5700000000045d888aeb1cc9119fe808002b10486002000000";



 send(socket:soc, data:hex2raw(s:bindstr));
 r = dcom_recv(socket:soc);
 if(!r)raisewarn(text:"check3: dcom_recv");

 send(socket:soc, data:req);
 r = dcom_recv(socket:soc);
 close(soc);
 if(!r)return NULL;


 error_code = substr(r, strlen(r) - 24, strlen(r) - 21);
 return error_code;
}


function check4(req)
{
  local_var soc,bindstr, error_code, r;
 
 
 soc = open_sock_tcp(port);
 if(!soc)raisewarn(text:"check4: open_sock");

 bindstr = "05000b03100000004800000002000000d016d016000000000100000001000100b84a9f4d1c7dcf11861e0020af6e7c5700000000045d888aeb1cc9119fe808002b10486002000000";



 send(socket:soc, data:hex2raw(s:bindstr));
 r = dcom_recv(socket:soc);
 if(!r)raisewarn(text:"check4: dcom_recv");

 send(socket:soc, data:req);
 r = dcom_recv(socket:soc);
 if(!r)return NULL;
 close(soc);


 error_code = substr(r, strlen(r) - 24, strlen(r) - 21);
 return error_code;
}


function check6(req)
{
  local_var soc,bindstr, error_code, r;
 
 
 soc = open_sock_tcp(port);
 if(!soc)raisewarn(text:"check6: open_sock");

 bindstr = "05000b031000000048000000deadbeefd016d016000000000100000000000100b84a9f4d1c7dcf11861e0020af6e7c5700000000045d888aeb1cc9119fe808002b10486002000000";





 send(socket:soc, data:hex2raw(s:bindstr));
 r = dcom_recv(socket:soc);
 if(!r)raisewarn(text:"check6: dcom_recv");

 send(socket:soc, data:req);
 r = dcom_recv(socket:soc);
 close(soc);
 if(!r)return NULL;


 error_code = substr(r, strlen(r) - 24, strlen(r) - 21);
 return error_code;
}

function req5()
{
 local_var name, buf, uname;
 

 name = get_smb_host_name();	
 if(!name)return NULL;
 
 name = "\\" + name + "\C$\";
 
 len = strlen(name) + 1;
 
 for(i=0;i<strlen(name);i++)
 { 
  uname += name[i] + raw_string(0);
 }
 
 if((strlen(name) & 1) == 0)  uname += raw_string(0, 0);
 
 
 len_lo = len % 256;
 len_hi = len / 256;
 
 
 
 buf = raw_string(0x05, 0x00,
 	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x96,
	0x95, 0x2A, 0x8c, 0xDA, 0x6D, 0x4a, 0xb2, 0x36,
	0x19, 0xBC, 0xAF, 0x2C, 0x2d, 0xea, 0x30, 0xeb,
	0x8F, 0x00, len_lo, len_hi, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, len_lo, len_hi, 0x00, 0x00) + uname +
	raw_string(
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0xdc, 0xea, 0x8f, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x95, 0x96, 0x95, 0x2A, 0x8C, 0xDA,
	0x6D, 0x4a, 0xb2, 0x36, 0x19, 0xbc, 0xaf, 0x2c,
	0x2d, 0xea, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x5C, 0x00);
 
 len  = strlen(buf);
 len_lo = len % 256;
 len_hi = len / 256;
 tlen = len + 24;
 tlen_lo = tlen % 256;
 tlen_hi = tlen / 256;
 head = raw_string(0x05, 0x00,
 	0x00, 0x03, 0x10, 0x00, 0x00, 0x00, tlen_lo, tlen_hi,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, len_lo,len_hi,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00) + buf;
 
 return head;
}

#---------------------------------------------------------------#
function raisewarn(text)
{
# results were indeterminate, stop false MS03-026 detection
 data = string("Network problems stopped us from finding out if the host is vulnerable to MS03-039 or not. Diagnostic = ", text);
 set_kb_item(name:"SMB/KB824146", value:TRUE); 
 security_warning(port:port, data:data);
 exit(0);
}
#---------------------------------------------------------------#


port = 135;
if(!get_port_state(port))port = 593;
else {
 soc = open_sock_tcp(port);
 if(!soc)port = 593;
 else close(soc);
}
if(!get_port_state(port))exit(0);

target = get_host_ip();
# Determine if we the remote host is running Win95/98/ME
bindwinme = "05000b03100000004800000053535641d016d016000000000100000000000100e6730ce6f988cf119af10020af6e72f402000000045d888aeb1cc9119fe808002b10486002000000";
soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:hex2raw(s:bindwinme));
rwinme = dcom_recv(socket:soc);
if(!rwinme)raisewarn(text:"main: dcom_recv");
close(soc);
lenwinme = strlen(rwinme);
stubwinme = substr(rwinme, lenwinme-24, lenwinme-21);

# This is Windows 95/98/ME which is not vulnerable
if("02000100" >< hexstr(stubwinme))exit(0);


#----------------------------------------------------------------#

REGDB_CLASS_NOTREG = "5401048000";
CO_E_BADPATH = "0400088000";
NT_QUOTE_ERROR_CODE_EQUOTE = "00000000";



#
req1 = "0500000310000000b00300000100000098030000000004000500020000000000000000000000000000000000000000000000000000000000000000009005140068030000680300004d454f5704000000a201000000000000c0000000000000463803000000000000c0000000000000460000000038030000300300000000000001100800ccccccccc80000000000000030030000d80000000000000002000000070000000000000000000000000000000000000018018d00b8018d000000000007000000b901000000000000c000000000000046ab01000000000000c000000000000046a501000000000000c000000000000046a601000000000000c000000000000046a401000000000000c000000000000046ad01000000000000c000000000000046aa01000000000000c0000000000000460700000060000000580000009000000058000000200000006800000030000000c000000001100800cccccccc5000000000000000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001100800cccccccc4800000000000000005d889aeb1cc9119fe808002b1048601000000000000000000000000100000000000000b8470a005800000005000600010000000000000000000000c000000000000046cccccccc01100800cccccccc80000000000000000000000000000000000000000000000020ba09000000000060000000600000004d454f5704000000c001000000000000c0000000000000463b03000000000000c000000000000046000000003000000001000100673c70941333fd4687244d093988939d0200000000000000000000000000000000000000000000000100000001100800cccccccc480000000000000000000000b07e09000000000000000000f0890a0000000000000000000d000000000000000d000000730061006a00690061006400650076005f0078003800360000000800cccccccc01100800cccccccc10000000000000000000000000000000000000000000000001100800cccccccc5800000000000000c05e0a000000000000000000000000001b000000000000001b0000005c005c0000005c006a00690061006400650076005f007800000036005c007000750062006c00690063005c004100410041004100000000000100150001100800cccccccc200000000000000000000000905b09000200000001006c00c0df0800010000000700550000000000";

req2 = "0500000310000000b00300000200000098030000000004000500020000000000000000000000000000000000000000000000000000000000000000009005140068030000680300004d454f5704000000a201000000000000c0000000000000463803000000000000c0000000000000460000000038030000300300000000000001100800ccccccccc80000000000000030030000d80000000000000002000000070000000000000000000000000000000000000018018d00b8018d000000000007000000b901000000000000c000000000000046ab01000000000000c000000000000046a501000000000000c000000000000046f601000000000000c000000000000046ff01000000000000c000000000000046ad01000000000000c000000000000046aa01000000000000c0000000000000460700000060000000580000009000000058000000200000006800000030000000c000000001100800cccccccc5000000000000000ffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001100800cccccccc4800000000000000005d889aeb1cc9119fe808002b1048601000000000000000000000000100000000000000b8470a005800000005000600010000000000000000000000c000000000000046cccccccc01100800cccccccc80000000000000000000000000000000000000000000000020ba09000000000060000000600000004d454f5704000000c001000000000000c0000000000000463b03000000000000c000000000000046000000003000000001000100673c70941333fd4687244d093988939d0200000000000000000000000000000000000000000000000100000001100800cccccccc480000000000000000000000b07e09000000000000000000f0890a0000000000000000000d000000000000000d000000730061006a00690061006400650076005f0078003800360000000800cccccccc01100800cccccccc10000000000000000000000000000000000000000000000001100800cccccccc5800000000000000c05e0a000000000000000000000000001b000000000000001b0000005c005c0000005c006a00690061006400650076005f007800000036005c007000750062006c00690063005c004100410041004100000000000100150001100800cccccccc200000000000000000000000905b09000200000001006c00c0df0800010000000700550000000000";


req3  = "05000e03100000004800000003000000d016d01605af00000100000001000100b84a9f4d1c7dcf11861e0020af6e7c5700000000045d888aeb1cc9119fe808002b10486002000000";
req4 = "05000003100000009a00000003000000820000000100000005000200000000000000000000000000000000000000000000000000000000009596952a8cda6d4ab23619bcaf2c2dea34eb8f000700000000000000070000005c005c004d0045004f00570000000000000000005c0048005c0048000100000058e98f00010000009596952a8cda6d4ab23619bcaf2c2dea01000000010000005c00";





#display(hex2raw(s:req));
#exit(0);



 
 

error1 = check(req:hex2raw(s:req1));
error2 = check(req:hex2raw(s:req2)); 


error3 = check(req:hex2raw(s:req3));
error4 = check2(req:hex2raw(s:req4));
error5 = NULL;
null_session_failed = 0;

if(hexstr(error1) == "00000000")
 {
  req = req5();
  if(req)
  	error5 = check4(req:req);
  else null_session_failed = 1;	
 }

#display(target, " error1=", hexstr(error1), "\n");
#display(target, " error2=", hexstr(error2), "\n");
#display(target, " error3=", hexstr(error3), "\n");
#display(target, " error4=", hexstr(error4), "\n");
#display(target, " error5=", hexstr(error5), "\n");


#KK 10/01/2004 - check if os = Windows NT 4.0 reset error4
    kb = get_kb_item("Host/OS/smb");
    if ( kb ) 
    {
       if ("Windows 4.0" >< kb  ) { error4 = ""; }
    }
#KK 

if(hexstr(error1) == "00000000" &&
   hexstr(error2) == "00000000" &&
   (hexstr(error4) == "1c00001c" || hexstr(error4) == "0300011c") &&
   isnull(error5)){
 	set_kb_item(name:"SMB/KB824146", value:TRUE);
	exit(0); # HP-UX dced or WinXP SP2
	}


#error5 = NULL;
#null_session_failed = 1;


if(hexstr(error2) == hexstr(error1))
{
 vulnerable = 1;
 if(hexstr(error1) == "05000780")exit(0); # DCOM disabled
 if(hexstr(error1) == "00000000")
 {
  if( hexstr(error5) == "04000880" )vulnerable = 0;
  else if( null_session_failed || hexstr(error5) == "05000780") { 
   req6 = "0500000310000000c600000000000000ae000000000000000500010000000000000000005b4e65737375735d5b4e65737375735d000000004e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e680f0b001e000000000000001e0000005c005c00410000005c000000630024005c0074006500730074005f0032003000300033005f006e00650073007300750073002e00740078007400000000000000020000000200000001000000b8eb0b00010000000000000000000000000000000000000001000000010000000700";
   error6 = check6(req:hex2raw(s:req6));
   req7 = "0500000310000000c600000000000000ae000000000000000500010000000000000000005b4e65737375735d5b4e65737375735d0000000048484848484848484848484848484848680f0b001e000000000000001e0000005c005c003100370032002e00340032002e003100340032002e0031003400320000005c0074006500730074005f004e0065007300730075007300000000000000020000000200000001000000b8eb0b00010000000000000000000000000000000000000001000000010000000700";
   error7 = check6(req:hex2raw(s:req7));
   if(hexstr(error6) == "54010480" && hexstr(error7) == "04000880")vulnerable = 0;
   #display(target, " error6=", hexstr(error6), "\n");
   #display(target, " error7=", hexstr(error7), "\n");
   if(hexstr(error6) == hexstr(error7) &&
      hexstr(error6) == "05000780")exit(0); # Dcom disabled
   
  }
 }
}
  
 
if(vulnerable)
{
 security_hole(port);
}
else {
 set_kb_item(name:"SMB/KB824146", value:TRUE);
}

