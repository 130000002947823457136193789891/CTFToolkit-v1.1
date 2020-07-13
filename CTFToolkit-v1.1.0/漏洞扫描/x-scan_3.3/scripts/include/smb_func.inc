# -*- Fundamental -*-
#
# 
# (C) 2005 Tenable Network Security
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# smb_func.inc 
# $Revision: 1.22 $
#

include ('smb_header.inc');
include ('kerberos_func.inc');

# GLOBAL VAR : Session. Can be used as arg later.
global_var Session;





function kb_smb_name()
{
 local_var ret;
 ret = get_kb_item("SMB/name");
 if ( ret ) 
	return string(ret);
 else
	return get_host_ip();
}

function kb_smb_domain()
{
 return string(get_kb_item("SMB/domain"));
}

function kb_smb_login()
{
 return string(get_kb_item("SMB/login"));
}

function kb_smb_password()
{
 return string(get_kb_item("SMB/password"));
}

function kb_smb_transport()
{
 local_var r;
 r = get_kb_item("SMB/transport");
 if ( r ) return int(r);
 else return 445;
}




#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#



#---------------------------------------------------------#
# Function    : get_string                                #
# Description : Extract a null terminated string          #
#---------------------------------------------------------#

function get_string (blob, pos, _type)
{
 local_var string, i, unicode;

 if (isnull (_type))
   unicode = session_is_unicode();
 else
   unicode = _type;

 string = NULL;
 i = pos;

 while (i < strlen(blob))
 {
  if (unicode == 1)
  {
   if ((blob[i] == '\0') && (blob[i+1] == '\0'))
    return unicode2ascii (string:string); 
   string += blob[i] + blob[i+1];
   i += 2;
  }
  else
  {
   if (blob[i] == '\0')
     return string;
   string += blob[i];
   i++;
  }
 }
}


#---------------------------------------------------------#
# Function    : get_string2                               #
# Description : Extract a non null terminated string      #
#---------------------------------------------------------#

function get_string2 (blob, pos, len, _type)
{
 local_var string, unicode;

 if (isnull (_type))
   unicode = session_is_unicode();
 else
   unicode = _type;

 string = NULL;

 if (pos+len > strlen(blob))
   return NULL;

 string = substr (blob, pos, pos+len-1);
 if (unicode == 1)
   return unicode2ascii (string:string); 
 else
   return string;
}


#---------------------------------------------------------#
# Function    : null_length                               #
# Description : return size of null end char              #
#---------------------------------------------------------#

function null_length ()
{
 if (session_is_unicode() == 1)
   return 2;
 else
   return 1;
}


#---------------------------------------------------------#
# Function    : dos_status                                #
# Description : Return DOS_status code                    #
#---------------------------------------------------------#

function dos_status (ErrorClass, ErrorCode)
{
 return  raw_byte (b:ErrorClass) +
         raw_byte (b:0) +
         raw_word (w:ErrorCode);
}


#---------------------------------------------------------#
# Function    : nt_status                                 #
# Description : Return NT_status code                     #
#---------------------------------------------------------#

function nt_status (Status)
{
 return raw_dword (d:Status);
}


#---------------------------------------------------------#
# Function    : ascii                                     #
# Description : Convert string to ASCII string (NULL end) #
#---------------------------------------------------------#

function ascii (string)
{
 return string + raw_byte (b:0);
}



#---------------------------------------------------------#
# Function    : unicode                                   #
# Description : Convert ASCII string to unicode           #
#---------------------------------------------------------#

function unicode (string)
{
 local_var ustring, i;

 ustring = NULL;

 for (i=0; i<strlen(string); i++)
 {
   ustring += string[i] + raw_byte (b:0);
 }

 return ustring;
}


#---------------------------------------------------------#
# Function    : unicode2ascii                             #
# Description : Convert unicode string to ascii           #
#---------------------------------------------------------#

function unicode2ascii (string)
{
 local_var astring, i;

 astring = NULL;

 for (i=0; i<strlen(string); i+=2)
 {
   astring += string[i];
 }

 astring -= '\0';
 return astring;
}


#---------------------------------------------------------#
# Function    : isUnicode                                 #
# Description : Return 1 if string is in real unicode     #
#---------------------------------------------------------#

function isUnicode (string)
{
 # Unicode are not supported yet in nessus
 return 0;
}


#---------------------------------------------------------#
# Function    : cstring                                   #
# Description : Convert string to ascii or unicode        #
#               If null is set, null end char is not      #
#               added                                     #
#---------------------------------------------------------#

function cstring (string, _null)
{
 local_var astring, ustring, i, sUnicode;

 sUnicode = session_is_unicode();

 # If the string is not in real unicode
 if (isUnicode (string:string) == 0)
 {
  if ( (!string && (_null == 1)) || ((sUnicode == 0) && (_null == 1)) )
    return string;
   
  if (sUnicode == 1)
  {
   if (_null == 1)
     return unicode (string:string);
   else
     return unicode (string:ascii(string:string));
  }
  else
    return ascii (string:string);
 }
 else
 {
  # sUnicode must be set to 1 in this case.
  if (_null == 1)
    return string;
  else
    return string + raw_string (0x00,0x00);
 }
}


function convert_time_to_sec (time)
{
 local_var high, low, add, tmp, tmp2, i, j, val;

 high = get_dword (blob:time, pos:4);
 low = get_dword (blob:time, pos:0);

 if ((low == 0) && (high == 0x80000000))
   return -1;

 # 0 - time
 if (low != 0)
   high = 0 - (high+1);
 else
   high = 0 - high;

 low = 0 - low;


 # >> 7
 tmp = (high & 0xFFFFFFF) << 25;
 high = high >> 7;

 low = (low >> 7) ^ tmp;

 tmp = raw_dword(d:low)+raw_dword(d:high);

 for (i=0; i<7; i++)
 {
  val = 0;
  tmp2 = NULL;
  for (j=0; j<8; j++)
  {
   tmp2 = raw_string((ord(tmp[7-j])+val*256)/5) + tmp2;
   val = (ord(tmp[7-j])+val*256)%5;
  }
  tmp = tmp2;
 }

 return get_dword(blob:tmp, pos:0);
}




#==================================================================#
# Section 2. Session functions                                     #
#==================================================================#


# Session structure (array):
#
# DWORD Socket;
# DWORD Timeout;
# WORD  Uid;
# WORD  Tid;
# WORD  Pid;
# WORD  Mid;
# BYTE  Unicode;
# DWORD cMaxBufferSize;
# DWORD SequenceNumber;
# BYTE  MAC_Key[];
# BYTE  Flags;
# WORD  Flags2;

function session_init (socket,timeout,login,domain,password,hostname)
{
 local_var session, host;

 Session[0] = socket;
 
 if (!isnull (timeout))
   Session[1] = timeout;
 else
   Session[1] = 15;

 if (isnull (hostname))
   host = NULL;
 else
 {
   host = hostname;
   while (host[strlen(host)-1] == ' ')
     host = substr(host,0,strlen(host)-2);
 }

 Session[2] = 0; # Uid
 Session[3] = 0; # Tid
 Session[4] = rand(); # Pid
 Session[5] = 0; # Mid
 Session[6] = 0; # Unicode
 Session[7] = 0x4400; # Client Max Buffer Size
 Session[8] = 0; # SequenceNumber
 Session[9] = NULL; # MAC_Key
 Session[10] = SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES;
 Session[11] = SMB_FLAGS2_KNOWS_LONG_NAMES | SMB_FLAGS2_32BIT_STATUS | SMB_FLAGS2_EAS;
 Session[12] = host;
 Session[13] = 0;
 Session[14] = 0; # GUEST
 Session[15] = 0; # cid
 Session[16] = 0; # Server Max buff size
}


function session_get_socket ()
{
 return Session[0];
}


function session_set_socket (socket)
{
 Session[0] = socket;
}


function session_get_timeout ()
{
 return Session[1];
}


function session_set_timeout (timeout)
{
 Session[1] = timeout;
}


function session_get_uid ()
{
 return Session[2];
}


function session_set_uid (uid)
{
 Session[2] = uid;
}


function session_get_tid ()
{
 return Session[3];
}


function session_set_tid (tid)
{
 Session[3] = tid;
}


function session_get_pid ()
{
 return Session[4];
}


function session_set_pid (pid)
{
 Session[4] = pid;
}


function session_get_mid ()
{
 local_var mid;

 mid = Session[5];
 Session[5] = mid + 64;

 return mid;
}


function session_set_mid (mid)
{
 Session[5] = mid;
}


function session_is_unicode ()
{
 return Session[6];
}


function session_set_unicode (unicode)
{
 if (unicode == 1)
   session_add_flags2 (flag:SMB_FLAGS2_UNICODE_STRINGS);
 else
 {
  if (session_is_unicode() == 1)
    session_del_flags2 (flag:SMB_FLAGS2_UNICODE_STRINGS);
 }
 Session[6] = unicode;
}


function session_get_buffersize ()
{
 return Session[7];
}


function session_set_buffersize (size)
{
 Session[7] = size;
}


function session_get_sequencenumber ()
{
 return Session[8];
}


function session_increase_sequencenumber ()
{
 Session[8] = Session[8] + 1;
}


function session_get_mackey ()
{
 return Session[9];
}


function session_set_mackey (key)
{
 Session[9] = key;
}


function session_get_flags ()
{
 return Session[10];
}


function session_add_flags (flag)
{
 Session[10] = Session[10] | flag;
}


function session_get_flags2 ()
{
 return Session[11];
}


function session_add_flags2 (flag)
{
 Session[11] = Session[11] | flag;
}


function session_del_flags2 (flag)
{
 Session[11] = Session[11] ^ flag;
}

function session_get_hostname ()
{
 return Session[12];
}


function session_set_hostname (hostname)
{
 Session[12] = hostname;
}


function session_is_authenticated ()
{
 return Session[13];
}


function session_set_authenticated ()
{
 Session[13] = 1;
}


function session_is_guest ()
{
 return Session[14];
}


function session_set_guest (guest)
{
 Session[14] = guest;
}


function session_get_cid ()
{
 local_var cid;

 cid = Session[15];
 Session[15] = cid + 1;

 return cid;
}


function session_set_server_max_size (size)
{
 Session[16] = size;
}


function session_get_server_max_size ()
{
 return Session[16];
}



#==================================================================#
# Section 3. SMB functions                                         #
#==================================================================#


#---------------------------------------------------------#
# Function    : smb_parameters                            #
# Description : Create SMB parameters structure           #
#---------------------------------------------------------#

function smb_parameters (data)
{
 local_var count;

 if ( !data )
   count = 0;
 else
   count = strlen (data) / 2;

 return raw_byte (b:count) + data;
}


#---------------------------------------------------------#
# Function    : smb_data                                  #
# Description : Create SMB data structure                 #
#---------------------------------------------------------#

function smb_data (data)
{
 local_var count;

 if ( isnull(data) )
   count = 0;
 else
   count = strlen (data);

 return raw_word (w:count) + data;
}


function netbios_header (type, length)
{
 return raw_byte (b:type) +
        raw_string ( (length>>16) & 255, (length>>8) & 255, (length) & 255 );
}


#---------------------------------------------------------#
# Function    : netbios_packet                            #
# Description : Convert SMB to netbios packet             #
#---------------------------------------------------------#
#                                                         #
# BYTE Type;       # 0 = session message                  #
# BYTE Length[3];  # length is on 24bits                  #
#                                                         #
#---------------------------------------------------------#

function netbios_packet (header,parameters,data)
{
 local_var length, netbios, head, hash, MAC, key;

 key = session_get_mackey();
 
 if (key)
 {
  hash = MD5 (key + header + parameters + data);
  MAC = substr( hash, 0, 7);
  head = substr (header, 0, 13) + MAC + substr (header, 22, 31);
 }
 else
   head = header;

 length = strlen (head) + strlen (parameters) + strlen (data);

 netbios = netbios_header (type:0, length:length) +
           head + parameters + data;

 return netbios;
}


#---------------------------------------------------------#
# Function    : smb_recv                                  #
# Description : Receive network smb packet                #
#---------------------------------------------------------#

function smb_recv ()
{
   local_var header, len, trailer, socket, timeout, tmp, hash, key;

   socket = session_get_socket ();
   timeout = session_get_timeout ();

   header = recv(socket:socket, length:4, min:4, timeout:timeout);
   if (strlen(header) < 4)
     return(NULL);
   
   len = 65535 * ord(header[1]) +
         256 * ord(header[2]) +
         ord(header[3]);
   
   if (len < 32)
     return (NULL);

   if (len > 100000)
     len = 100000;

   trailer = recv(socket:socket, length:len, min:len, timeout:timeout);
   if (strlen(trailer) < len )
     return(NULL);

   if ( session_get_mackey() )
   {
    key = session_get_mackey();

    tmp = substr (trailer,0,13) + raw_dword (d:session_get_sequencenumber()) + raw_dword (d:0) + substr (trailer, 22, strlen(trailer)-1);
    hash = substr(MD5 (key + tmp),0,7);

    # if signature is not correct we stop
    if (hash >!< substr(trailer, 14, 21))
    {
     if (strlen (key) == 16)
     {
       session_set_mackey (key:crap(data:raw_string(0),length:16));
       tmp = substr (trailer,0,13) + raw_dword (d:session_get_sequencenumber()) + raw_dword (d:0) + substr (trailer, 22, strlen(trailer)-1);
       hash = substr(MD5 (session_get_mackey () + tmp),0,7);

       # if signature is not correct we stop
       if (hash >!< substr(trailer, 14, 21))
         return NULL;
     }
     else
       return NULL;
    }
   }

   if (session_get_mackey())
     session_increase_sequencenumber();

   return trailer;
}


#---------------------------------------------------------#
# Function    : smb_sendrecv                              #
# Description : Perform a client/server exchange          #
#---------------------------------------------------------#

function smb_sendrecv(data)
{
 local_var socket;

 socket = session_get_socket();
 
 send (socket:socket, data:data);
 
 if (session_get_mackey())
   session_increase_sequencenumber();

 return smb_recv ();
}


#---------------------------------------------------------#
# Function    : get_header_flags                          #
# Description : Extract Flags                             #
#---------------------------------------------------------#

function get_header_flags(header)
{
 return get_byte (blob:header, pos:9);
}


#---------------------------------------------------------#
# Function    : get_header_flags2                         #
# Description : Extract Flags2                            #
#---------------------------------------------------------#

function get_header_flags2(header)
{
 return get_word (blob:header, pos:10);
}


#---------------------------------------------------------#
# Function    : get_header_dos_error_code                 #
# Description : Extract DOS Error code                    #
#---------------------------------------------------------#

function get_header_dos_error_code(header)
{
 return get_word (blob:header, pos:7);
}


#---------------------------------------------------------#
# Function    : get_header_nt_error_code                  #
# Description : Extract NT Error code                     #
#---------------------------------------------------------#

function get_header_nt_error_code(header)
{
 return get_dword (blob:header, pos:5);
}


#---------------------------------------------------------#
# Function    : get_header_command_code                   #
# Description : Extract Command code                      #
#---------------------------------------------------------#

function get_header_command_code(header)
{
 return get_byte (blob:header, pos:4);
}


#---------------------------------------------------------#
# Function    : get_header_uid                            #
# Description : Extract User ID                           #
#---------------------------------------------------------#

function get_header_uid(header)
{
 return get_word (blob:header, pos:28);
}


#---------------------------------------------------------#
# Function    : get_header_tid                            #
# Description : Extract Tree ID                           #
#---------------------------------------------------------#

function get_header_tid(header)
{
 return get_word (blob:header, pos:24);
}


#---------------------------------------------------------#
# Function    : get_header_signature                      #
# Description : Extract Signature                         #
#---------------------------------------------------------#

function get_header_signature(header)
{
 return substr (header,14,21);
}


#---------------------------------------------------------#
# Function    : get_smb_header                            #
# Description : Extract SMB header from blob              #
#---------------------------------------------------------#

function get_smb_header(smbblob)
{
 if (strlen (smbblob) < SMB_HDR_SIZE)
   return NULL;

 return substr (smbblob, 0, SMB_HDR_SIZE - 1);
}


#---------------------------------------------------------#
# Function    : get_smb_parameters                        #
# Description : Extract SMB parameters from blob          #
#---------------------------------------------------------#

function get_smb_parameters(smbblob)
{
 local_var WordCount;

 if (strlen (smbblob) < SMB_HDR_SIZE + 1)
   return NULL;

 WordCount = get_byte (blob:smbblob, pos:SMB_HDR_SIZE);
 if (strlen (smbblob) < (SMB_HDR_SIZE + 1 + WordCount * 2))
   return NULL;

 return substr (smbblob, SMB_HDR_SIZE + 1, SMB_HDR_SIZE + 1 + WordCount * 2);
}


#---------------------------------------------------------#
# Function    : get_smb_data                              #
# Description : Extract SMB data from blob                #
#---------------------------------------------------------#

function get_smb_data(smbblob)
{
 local_var WordCount, ByteCount, pos;

 if (strlen (smbblob) < SMB_HDR_SIZE + 1)
   return NULL;

 WordCount = get_byte (blob:smbblob, pos:SMB_HDR_SIZE);
 if (strlen (smbblob) < (SMB_HDR_SIZE + 1 + WordCount * 2 + 2))
   return NULL;
  
 pos = SMB_HDR_SIZE + 1 + WordCount * 2;
 
 ByteCount = get_word (blob:smbblob, pos:pos);
 if (strlen (smbblob) < (pos + 2 + ByteCount))
   return NULL;


 return substr (smbblob, pos + 2, pos + 2 + ByteCount - 1);
}


#---------------------------------------------------------#
# Function    : smb_header                                #
# Description : Generate header of SMB packet             #
#---------------------------------------------------------#
#                                                         #
# SMB header structure                                    #
#					                  #
# struct {                                                #
#   BYTE  Protocol[4];      # "\xFFSMB"                   #
#   BYTE  Command;                                        #
#   DWORD Status;           # Or BYTE ErrorClass;         #
#                           #    BYTE Reserved;           #
#                           #    WORD Error;              #
#   BYTE  Flags;                                          #
#   WORD  Flags2;                                         #
#   WORD  PidHigh;          # 0 like noone know it        #
#   BYTE  Signature[8];                                   #
#   WORD  Reserved;                                       #
#   WORD  Tid;              # Tree ID                     #
#   WORD  Pid;              # Process ID                  #
#   WORD  Uid;              # User ID                     #
#   WORD  Mid;              # Multiplex ID                #
# }                                                       #
#                                                         #
#---------------------------------------------------------#

function smb_header (Command, Status, Flags, Flags2)
{
 local_var header, fl, fl2;

 if (!isnull (Flags))
   fl = Flags;
 if (!isnull (Flags2))
   fl2 = Flags2;
   
 header = '\xFFSMB';
 header += raw_byte(b:Command);
 header += Status;
 header += raw_byte (b:session_get_flags() | fl);
 header += raw_word (w:session_get_flags2() | fl2);
 header += raw_word (w:0);
 header += raw_dword (d:session_get_sequencenumber()) + raw_dword (d:0);
 header += raw_word (w:0);
 header += raw_word (w:session_get_tid());
 header += raw_word (w:session_get_pid());
 header += raw_word (w:session_get_uid());
 header += raw_word (w:session_get_mid());

 return header;
}



function smb_check_success (data)
{
 local_var header, flags2, code;
 
 # Some checks in the header first
 header = get_smb_header (smbblob:data);
 if (!header)
   return FALSE;

 flags2 = get_header_flags2 (header:header);
 if (flags2 & SMB_FLAGS2_32BIT_STATUS)
 {
   code = get_header_nt_error_code (header:header);
   if (code != STATUS_SUCCESS)
     return FALSE;
 }
 else
 {
   code = get_header_dos_error_code (header:header);
   if (code != NO_ERROR)
     return FALSE;
 }

 return TRUE;
}


#-----------------------------------------------------------------#
# Encode name and service to the netbios network format           #
#-----------------------------------------------------------------#

function netbios_encode(data,service)
{
 local_var tmpdata, ret, i, o, odiv, omod, c;

 ret = "";
 tmpdata = data;

 while (strlen(tmpdata) < 15)
 {
   tmpdata += " ";
 }

 tmpdata += raw_string(service);

 for(i=0;i<16;i=i+1)
 {
   o = ord(tmpdata[i]);
   odiv = o/16;
   odiv = odiv + ord("A");
   omod = o%16;
   omod = omod + ord("A");
   c = raw_string(odiv, omod);

   ret = ret+c;
 }

 return raw_byte (b:strlen(ret)) + ret;
}


#-----------------------------------------------------------------#
# Convert a netbios name to the netbios network format            #
#-----------------------------------------------------------------#

function netbios_name(orig)
{
 return netbios_encode(data:orig, service:0x20);
}


function netbios_sendrecv (type, data)
{
 local_var req, socket, timeout, header, len, trailer;

 req = netbios_header (type:type, length:strlen(data)) +
       data;

 socket = session_get_socket();
 timeout = session_get_timeout ();

 send (socket:socket, data:req);

 header = recv(socket:socket, length:4, min:4, timeout:timeout);
 if (strlen(header) < 4)
   return(NULL);
   
 len = 65535 * ord(header[1]) +
       256 * ord(header[2]) +
       ord(header[3]);

 if (len > 100000)
   len = 100000;

 trailer = recv(socket:socket, length:len, min:len, timeout:timeout);
 if (strlen(trailer) < len )
   return(NULL);

 return header + trailer;
}





#==================================================================#
# Section 4. Netbios Functions                                     #
#==================================================================#

function netbios_session_request ()
{
 local_var req, resp, rep, port, called_name, calling_name, name;

 port = kb_smb_transport ();
 if (port == 445)
   return TRUE;

 name = get_kb_item ("SMB/netbios_name");
 if (name == TRUE)
   called_name = netbios_name (orig:session_get_hostname());
 else
   called_name = netbios_name (orig:"*SMBSERVER");

 calling_name = netbios_name (orig:NULL);

 data = called_name + raw_byte (b:0) +
        calling_name + raw_byte (b:0);
 rep = netbios_sendrecv (type:0x81, data:data);
 if (!rep)
   return NULL;

 if (ord(rep[0]) != 0x82)
   return FALSE;

 return TRUE;
}



#==================================================================#
# Section 4a. CIFS Functions                                       #
#==================================================================#


#---------------------------------------------------------#
# Function    : smb_negotiate_protocol                    #
# Description : Negotiate the SMB protocol to use         #
#---------------------------------------------------------#
#                                                         #
# SMB header :                                            #
#    Command : SMB_COM_NEGOTIATE                          #
#              Status = STATUS_SUCCESS                    #
#              Flags  = SMB_FLAGS_CANONICAL_PATHNAMES |   #
#                       SMB_FLAGS_CASELESS_PATHNAMES      #
#              Flags2 = SMB_FLAGS2_UNICODE_STRINGS |      #
#                       SMB_FLAGS2_KNOWS_LONG_NAMES       #
#              PidHig = 0                                 #
#              Signature = NULL (0,0..)                   #
#              Tid    = 0                                 #
#              Uid    = 0                                 #
#              Mid    = 2                                 #
#                                                         #
# SMB parameters :                                        #
#   BYTE  WordCount;      # 0                             #
#                                                         #
# SMB data :                                              #
#   WORD ByteCount;       # Number of byte                #
#   {                                                     #
#    BYTE BufferFormat;   # 0x02 (Dialect)                #
#    BYTE Name[];         # NTLM 0.12                     #
#   }                                                     #
#   {                                                     #
#    ...                  # PC NETWORK PROGRAM 1.0        #
#                         # MICROSOFT NETWORKS 1.03       #
#                         # MICROSOFT NETWORKS 3.0        #
#                         # LANMAN1.0                     #
#                         # LM1.2X002                     #
#                         # Samba                         #
#                         # NT LANMAN 1.0                 #
#   }                     # NT LM 0.12                    #
#                                                         #
#---------------------------------------------------------#

function smb_negotiate_protocol ()
{
 local_var header, parameters, data, packet, ret, i;
 
 header = smb_header (Command: SMB_COM_NEGOTIATE,
                      Status: nt_status (Status: STATUS_SUCCESS),
                      Flags2: SMB_FLAGS2_EXTENDED_SECURITY);

 parameters = smb_parameters (data:NULL); # No parameters

 data = NULL;
 for (i = 0; i < supported_protocol; i++)
 {
  data += raw_byte (b:0x02) + ascii (string:protocol[i]);
 }

 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 return smb_sendrecv (data:packet);
}




#---------------------------------------------------------#
# Function    : smb_session_setup_andx_lanman_core        #
# Description : Create SMB packet for LANMAN2.1 setupandx #
#---------------------------------------------------------#
#                                                         #
# SMB parameters :                                        #
#   BYTE  WordCount;                                      #
#   BYTE  Command;                                        #
#   BYTE  Reserved;                                       #
#   WORD  Offset;                                         #
#   WORD  MaxBufferSize;                                  #
#   WORD  MaxMpxCount;                                    #
#   WORD  VcNumber;                                       #
#   DWORD SessionKey;                                     #
#   WORD  PasswordLength;                                 #
#   DWORD Reserved;                                       #
#                                                         #
# SMB data :                                              #
#   WORD ByteCount;                                       #
#   BYTE Password[];                                      #
#   BYTE AccountName[];                                   #
#   BYTE PrimaryDomain[];                                 #
#   BYTE NativeOS[];                                      #
#   BYTE NativeLanMan[];                                  #
#                                                         #
#---------------------------------------------------------#

function smb_session_setup_andx_lanman_core (session_key,login,domain,password,mode,challenge)
{
 local_var name,dom,pass,header,parameters,data,packet,response,code,flags2,skey,guest;
 
 header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 # LANMAN2.1 names are uppercase and ascii
 name = toupper(login);
 dom = toupper (domain);
 pass = toupper (password);
 
 # If challenge/response mode we generate the response, else we keep plain text password
 if (pass && (mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE))
 {
  response = LM_Response (password:cstring (string:pass), challenge:challenge);

  pass = response[0];
  skey = response[1] + response[0];
 }
 
 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:session_get_buffersize()) +
              raw_word (w:1) +
              raw_word (w:0) +
              raw_dword (d:session_key) +
              raw_word (w:strlen(pass)) +
              raw_dword (d:0);
 
 parameters = smb_parameters (data:parameters);
  
 data = pass +
        cstring (string:name) +
        cstring (string:dom) +
        cstring (string:"Unix") +
        cstring (string:"Nessus");

 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet);
 if (!ret)
   return NULL;

 if (smb_check_success (data:ret) == FALSE)
   return NULL;
 
 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;

 sig = hexstr (get_header_signature (header:header));
 if ("0000000000000000" >!< sig)
 {
  # Security signatures are enabled only if server support them
  if (!session_get_mackey());
    session_set_mackey (key:skey);

  # we need to mark 2 previous exchange as signed
  session_increase_sequencenumber();
  session_increase_sequencenumber();
 }

 uid = get_header_uid (header:header);
 session_set_uid (uid:uid);

 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters || (strlen(parameters) < 6))
   return NULL;
 
 guest = get_word (blob:parameters, pos:4);
 session_set_guest (guest:guest);

 return packet; 
}



#---------------------------------------------------------#
# Function    : smb_session_setup_andx_ntlm_core          #
# Description : Create SMB packet for NTLM setupandx      #
#---------------------------------------------------------#
#                                                         #
# SMB parameters :                                        #
#   BYTE  WordCount;                                      #
#   BYTE  Command;                                        #
#   BYTE  Reserved;                                       #
#   WORD  Offset;                                         #
#   WORD  MaxBufferSize;                                  #
#   WORD  MaxMpxCount;                                    #
#   WORD  VcNumber;                                       #
#   DWORD SessionKey;                                     #
#   WORD  CaseInsensitivePasswordLength;                  #
#   WORD  CaseSensitivePasswordLength;                    #
#   DWORD Reserved;                                       #
#   DWORD Capabilities;                                   #
#                                                         #
# SMB data :                                              #
#   WORD  ByteCount;                                      #
#   BYTE  CaseInsensitivePassword[];                      #
#   BYTE  CaseSensitivePassword[];                        #
#   BYTE  Pad;        # present with unicode only         #   
#   BYTE  AccountName[];                                  #
#   BYTE  PrimaryDomain[];                                #
#   BYTE  NativeOS[];                                     #
#   BYTE  NativeLanMan[];                                 #
#   BYTE  Pad2[];     # seems to be optionnal             #
#                                                         #
#---------------------------------------------------------#

function smb_session_setup_andx_ntlm_core (session_key,login,domain,password,mode,challenge,version)
{
 local_var name,dom,pass,spass,ipass,header,parameters,data,packet,response,code,flags2,skey,guest;
 
 header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 if (!(mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE))
 {
  # SAMBA servers support plain text password in NTLM.
  # Implementing CIFS don't know exactly how to do with password.
  # Need to look at SAMBA code
  return NULL;
 }

 ipass = spass = NULL;

 # NTLM use only unicode password
 if (session_is_unicode() == 0)
 {
  session_set_unicode (unicode:1);
  pass = cstring (string:password, _null:1);
  name = cstring (string:login, _null:1);
  dom = cstring (string:domain, _null:1);  
  session_set_unicode (unicode:0);
 }
 else
 {
  pass = cstring (string:password, _null:1);
  name = cstring (string:login, _null:1);
  dom = cstring (string:domain, _null:1);  
 }
 
 # If challenge/response mode we generate the response, else we keep plain text password
 if (pass && (mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE))
 {
  # NOT WORKING !
  #response= NTLMv2_Response (password:pass, login:name, domain:dom, challenge:challenge);
  #spass = response[0];
  
  if (version == 2)
  {
    response = LMv2_Response (password:pass, login:name, domain:dom, challenge:challenge);
    ipass = response[0];
    # Windows allways use unicode password for mac key
    # like it is null (NTLMv2 to fix) we use a null byte [16] array
    skey = response[1];
  }
  else
  {
    response = NTLM_Response (password:pass, challenge:challenge);
    spass = response[0];
    skey = response[1] + response[0];
  }

  # Security signatures are enabled only if server support them
  if (!session_get_mackey() && ((mode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED) || (mode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED)))
    session_set_mackey (key:skey);

 }
 
 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:session_get_buffersize()) +
              raw_word (w:1) +
              raw_word (w:0) +
              raw_dword (d:session_key) +
	      raw_word (w:strlen(ipass)) +
              raw_word (w:strlen(spass)) +
              raw_dword (d:0) +
	      raw_dword (d: CAP_UNICODE * session_is_unicode() | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_NT_FIND );
 
 parameters = smb_parameters (data:parameters);
 
 # If Unicode we must add 1 byte pad
 if (session_is_unicode() == 1)
   spass += raw_string(0x00);
   
 data = ipass + spass +
        cstring (string:login) +
        cstring (string:domain) +
        cstring (string:"Unix") +
        cstring (string:"Nessus");
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet);
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;

 uid = get_header_uid (header:header);
 session_set_uid (uid:uid);

 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters || (strlen(parameters) < 6))
   return NULL;
 
 guest = get_word (blob:parameters, pos:4);
 session_set_guest (guest:guest);

 return packet; 
}



#---------------------------------------------------------#
# Function    : smb_session_setup_andx_kerberos_core      #
# Description : Create SMB packet for Kerberos setupandx  #
#---------------------------------------------------------#

function smb_session_setup_andx_kerberos_core (session_key,login,password,realm,host,mode)
{
 local_var name,dom,pass,spass,ipass,header,parameters,data,packet,response;
 local_var uid, bloblength, securityblob, guest, key;

 header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 kerb_data = kerberos_securityblob (login:login,password:password,realm:realm,host:host);
 if (isnull(kerb_data))
   return NULL;
   
 securityblob = kerb_data[1];
 
 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:session_get_buffersize()) +
              raw_word (w:1) +
              raw_word (w:0) +
              raw_dword (d:session_key) +
              raw_word (w:strlen(securityblob)) +
              raw_dword (d:0) +
	      raw_dword (d: CAP_UNICODE * session_is_unicode() | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_NT_FIND | CAP_EXTENDED_SECURITY);
 
 parameters = smb_parameters (data:parameters);
 
 # If strlen (securityblob) odd add 1 pad byte
 if ((strlen (securityblob) % 2) == 0)
   securityblob += raw_string(0x00);
   
 data = securityblob + 
        cstring (string:"Unix") +
        cstring (string:"Nessus");
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet);
 if (!ret)
   return NULL;
 
 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;

 flags2 = get_header_flags2 (header:header);
 if (flags2 & SMB_FLAGS2_32BIT_STATUS)
 {
   code = get_header_nt_error_code (header:header);
   if (code != STATUS_SUCCESS)
     return NULL;
 }
 else
 {
   code = get_header_dos_error_code (header:header);
   if (code != NO_ERROR)
     return NULL;
 }

 uid = get_header_uid (header:header);
 session_set_uid (uid:uid);
 
 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters || (strlen(parameters) < 8))
   return NULL;
 
 guest = get_word (blob:parameters, pos:4);
 session_set_guest (guest:guest);

 bloblength = get_word (blob:parameters, pos:6);
 
 # We now parse/take information in SMB parameters
 data = get_smb_data (smbblob:ret);
 if (!data)
   return NULL;
  
 if (strlen(data) < bloblength)
   return NULL;
 
 securityblob = substr (data, 0, bloblength - 1);
 if (!securityblob)
   return NULL;

 key = check_kerberos_response (data:securityblob, key:kerb_data[0]);
 if (isnull(key))
   return NULL;

 if (!session_get_mackey() && ((mode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED) || (mode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED)) && (login))
 {
  if (key[0] == 0)
    session_set_mackey (key:kerb_data[0]);
  else
    session_set_mackey (key:key[1]);

  session_increase_sequencenumber();
  session_increase_sequencenumber();
 }

 return packet; 
}


#---------------------------------------------------------#
# Function    : smb_session_setup_andx_ntlmssp_core       #
# Description : Create SMB packet for ntlmssp setupandx   #
#---------------------------------------------------------#

function smb_session_setup_andx_ntlmssp_core (session_key,login,password,domain,mode)
{
 local_var name,dom,pass,header,parameters,data,packet,response,uid,guest;
 local_var challenge, securityblob,securityblob_length;

 header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 securityblob = ntlmssp_negotiate_securityblob ();

 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:session_get_buffersize()) +
              raw_word (w:1) +
              raw_word (w:1) +
              raw_dword (d:session_key) +
              raw_word (w:strlen(securityblob)) +
              raw_dword (d:0) +
	      raw_dword (d: CAP_UNICODE * session_is_unicode() | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_NT_FIND | CAP_EXTENDED_SECURITY);
 
 parameters = smb_parameters (data:parameters);
 
 # If strlen (securityblob) odd add 1 pad byte
 if ((strlen (securityblob) % 2) == 0)
   securityblob += raw_string(0x00);
   
 data = securityblob + 
        cstring (string:"Unix") +
        cstring (string:"Nessus") +
	cstring (string:domain);
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;

 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;
 
 code = get_header_nt_error_code (header:header);
 if (code != STATUS_MORE_PROCESSING_REQUIRED)
   return NULL;

 uid = get_header_uid (header:header);
 session_set_uid (uid:uid);
 
 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters)
   return NULL;
 
 bloblength = get_word (blob:parameters, pos:6);
 
 # We now parse/take information in SMB parameters
 data = get_smb_data (smbblob:ret);
 if (!data)
   return NULL;
  
 if (strlen(data) < bloblength)
   return NULL;
 
 securityblob = substr (data, 0, bloblength - 1);
 
 challenge = ntlmssp_parse_challenge (data:securityblob);
 if (!challenge)
   return NULL;

 if (login)
 {
  # NTLM use only unicode password
  if (session_is_unicode() == 0)
  {
   session_set_unicode (unicode:1);
   if (password)
     pass = cstring (string:password, _null:1);
   else
     pass = NULL;
   name = cstring (string:login, _null:1);
   dom = cstring (string:domain, _null:1);  
   session_set_unicode (unicode:0);
  }
  else
  {
   pass = cstring (string:password, _null:1);
   name = cstring (string:login, _null:1);
   dom = cstring (string:domain, _null:1);  
  }
 }
 else
 {
  name = NULL;
  pass = NULL;
  dom = NULL;
 }
 securityblob = ntlmssp_auth_securityblob (password:pass,login:name,domain:dom,challenge:challenge);
 if (isnull(securityblob))
   return NULL;

 # Security signatures are enabled only if server support them
 # We use null session_key as we used LMv2 only
 if (!session_get_mackey() && ((mode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED) || (mode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED)) && (login))
  # session_set_mackey (key:crap(data:raw_string(0),length:16));
   session_set_mackey (key:securityblob[0]);

 securityblob = securityblob[1];

 header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:session_get_buffersize()) +
              raw_word (w:1) +
              raw_word (w:0) +
              raw_dword (d:session_key) +
              raw_word (w:strlen(securityblob)) +
              raw_dword (d:0) +
	      raw_dword (d: CAP_UNICODE * session_is_unicode() | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_NT_FIND | CAP_EXTENDED_SECURITY);
 
 parameters = smb_parameters (data:parameters);
 
 # If strlen (securityblob) odd add 1 pad byte
 if ((strlen (securityblob) % 2) == 0)
   securityblob += raw_string(0x00);
   
 data = securityblob + 
        cstring (string:"Unix") +
        cstring (string:"Nessus") +
	cstring (string:domain);
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);
 
 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;

 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;
 
 code = get_header_nt_error_code (header:header);
 if (code != STATUS_SUCCESS)
   return NULL;

 uid = get_header_uid (header:header);
 session_set_uid (uid:uid);
 
 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters || (strlen(parameters) < 8))
   return NULL;

 guest = get_word (blob:parameters, pos:4);
 session_set_guest (guest:guest);

 bloblength = get_word (blob:parameters, pos:6);
 # We now parse/take information in SMB parameters
 data = get_smb_data (smbblob:ret);
 if (!data)
   return NULL;
  
 if (strlen(data) < bloblength)
   return NULL;
 
 securityblob = substr (data, 0, bloblength - 1);

 challenge = ntlmssp_parse_response (data:securityblob);
 if (isnull(challenge) || (challenge != 0)) # Accept Completed
   return NULL;

 return packet;
}




#---------------------------------------------------------#
# Function    : smb_session_setup_andx                    #
# Description : Authenticate to the remote host           #
#---------------------------------------------------------#

function smb_session_setup_andx (session_key, dialect, challenge, mode, extended, login, password, domain, host, realm)
{
 local_var packet, ct, onlyv2;

 # If cleartext is prohibited we return NULL
 ct = get_kb_item("SMB/dont_send_in_cleartext");
 if ((ct == "yes") && (!(mode & NEGOTIATE_SECURITY_CHALLENGE_RESPONSE))) return NULL;

 onlyv2 = get_kb_item ("SMB/dont_send_ntlmv1");

 # If LANMAN2.1 protocol
 if (protocol[dialect] == "LANMAN2.1")
 {
  if (onlyv2) return NULL;

  packet = smb_session_setup_andx_lanman_core (session_key:session_key,
                                               login:login,
					       domain:domain,
					       password:password,
					       mode:mode,
					       challenge:challenge);
  return packet;
 }
 # If NT LM 0.12 protocol
 if (protocol[dialect] == "NT LM 0.12")
 {
  if (isnull (extended))
  {
   packet = smb_session_setup_andx_ntlm_core (session_key:session_key,
                                              login:login,
 	 				      domain:domain,
 					      password:password,
					      mode:mode,
					      challenge:challenge,
					      version:2);

   if (! packet )
   {
    if (onlyv2) return NULL;

    packet = smb_session_setup_andx_ntlm_core (session_key:session_key,
                                              login:login,
 	 				      domain:domain,
					      password:password,
 					      mode:mode,
					      challenge:challenge,
					      version:1);
   }
   return packet;
  }
  else
  {
   if ((extended == 2) && defined_func ("open_sock_kdc") && login && password)
   {
    # If Kerberos
    packet = smb_session_setup_andx_kerberos_core (session_key:session_key,
    						   login:login,
						   password:password,
						   host:host,
						   realm:realm,
                                                   mode:mode);

    if (!isnull (packet))
      return packet;
   }
   
   # If NTLMSSP or if Kerberos failed
   packet = smb_session_setup_andx_ntlmssp_core (session_key:session_key,
   						 login:login,
						 password:password,
						 domain:domain,
                                                 mode:mode);
   return packet;
  }
 }
}




#---------------------------------------------------------#
# Function    : smb_login                                 #
# Description : Negotiate authentication  with remote     #
#               host.                                     #
# Return      : Return 1 on success , 0 on failure        #
#---------------------------------------------------------#

function smb_login (login,password,domain)
{
 local_var ret, code, flags2, header, parameters, data, unicode, SecurityBlob, ServerGUID;
 local_var DialectIndex, SecurityMode, MaxBufferSize, SessionKey, Capabilities, EncryptionKeyLength, EncryptionKey, Extended;
 local_var realm,host;
 local_var spnego;

 host = realm = NULL;

 #
 # First step : Protocol negotiation 
 #
 ret = smb_negotiate_protocol ();
 if (!ret)
   return NULL;
 
 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;

 flags2 = get_header_flags2 (header:header);
 if (flags2 & SMB_FLAGS2_32BIT_STATUS)
 {
  code = get_header_nt_error_code (header:header);
  if (code != STATUS_SUCCESS)
    return code;
 }
 else
 {
  code = get_header_dos_error_code (header:header);
  if (code != NO_ERROR)
    return code;
 }

 code = get_header_command_code (header:header);
 if (code != SMB_COM_NEGOTIATE)
   return ERROR_BAD_COMMAND;

 # We must get unicode or not here
 unicode = flags2 & SMB_FLAGS2_UNICODE_STRINGS;

 # We now parse/take information in SMB parameters
 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters)
   return NULL;
 
 # Negotiate protocol response parameters
 # NT LM 0.12                        LANMAN2.1
 # WORD  DialectIndex;               WORD  DialectIndex;
 # BYTE  SecurityMode;               WORD  SecurityMode;
 # WORD  MaxMpxCount;                WORD  MaxBufferSize;
 # WORD  MaxNumberVCs;               WORD  MaxMpxCount;
 # DWORD MaxBufferSize;              BYTE  MaxNumberVCs;
 # DWORD MaxRawSize;                 WORD  RawMode;
 # DWORD SessionKey;                 DWORD SessionKey;
 # DWORD Capabilities;               WORD  ServerTime;
 # DWORD SystemTimeLow;              WORD  ServerDate;
 # DWORD SystemTimeHigh;             WORD  ServerTimeZone;
 # WORD  ServerTimeZone;             WORD  EncryptionKeyLength;
 # BYTE  EncryptionKeyLength;        WORD  Reserved;
 # WORD  Reserved; 

 DialectIndex = get_word (blob:parameters, pos:0);

 if (DialectIndex > (supported_protocol-1))
 {
   # Bad server's response. Because it asks for an unsupported protocol
   return NULL;
 }

 Extended = NULL;

 if (protocol[DialectIndex] == "NT LM 0.12")
 {
  SecurityMode = get_byte (blob:parameters, pos:2);
  MaxBufferSize = get_dword (blob:parameters, pos:7);
  SessionKey = get_dword (blob:parameters, pos:15);
  Capabilities = get_dword (blob:parameters, pos:19);
  EncryptionKeyLength = get_byte (blob:parameters, pos:33);
 
  if (Capabilities & CAP_UNICODE)
    session_set_unicode (unicode:1);
  else
    session_set_unicode (unicode:0);
    
  if ((SecurityMode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED) || (SecurityMode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED))
    session_add_flags2 (flag:SMB_FLAGS2_SECURITY_SIGNATURE);

  if (Capabilities & CAP_EXTENDED_SECURITY)
    session_add_flags2 (flag:SMB_FLAGS2_EXTENDED_SECURITY);
 
  # We now parse/take information in SMB parameters
  data = get_smb_data (smbblob:ret);
  if (!data)
    return NULL;
 
  # Negotiate protocol response data for NTLM
  # BYTE EncryptionKey[];
  # BYTE DomainName[]; // NULL terminated
  # BYTE ServerName[]; // NULL terminated

  if (Capabilities & CAP_EXTENDED_SECURITY)
  {
   if (strlen(data) < 16)
     return NULL;
   ServerGUID = substr (data, 0, 15);
   if ((strlen (data) > 16) && (login && password))
   {
     SecurityBlob = substr (data, 16, strlen(data) - 1);
     spnego = der_parse_spnego_init (sdata:SecurityBlob);
     if (!isnull (spnego) && (spnego[3] != NULL))
     {
       michlist = spnego[3];
       host = ereg_replace (pattern:"(.*)\$@.*", string:michlist, replace:"\1");
       realm = ereg_replace (pattern:".*\$@(.*)", string:michlist, replace:"\1");
       Extended = 2; # Kerberos
     }
     else
       Extended = 1;
   }
   else
   {
     Extended = 1; # NTLMSSP
     SecurityBlob = NULL;
   }
  }
  else
  {
   if (EncryptionKeyLength != 0)
     EncryptionKey = substr (data, 0, 7); # Allways 8 byte length
   else
     EncryptionKey = NULL;

   if (strlen(data) > 8)
     DomainName = get_string (blob:data, pos:8);
  
   next = strlen(DomainName) + null_length();
   next += strlen(EncryptionKey);
  
   if (next  < strlen(data))
     ServerName = get_string (blob:data, pos:next);
  }
 }
 
 else if (protocol[DialectIndex] == "LANMAN2.1")
 {
  #LANMAN2.1 does not support unicode
  session_set_unicode (unicode:0);
  
  SecurityMode = get_word (blob:parameters, pos:2);
  MaxBufferSize = get_word (blob:parameters, pos:4);
  SessionKey = get_dword (blob:parameters, pos:11);
  EncryptionKeyLength = get_word (blob:parameters, pos:21);
  
  # We now parse/take information in SMB parameters
  data = get_smb_data (smbblob:ret);
  if (!data)
    return NULL;
  
  # BYTE EncryptionKey[];
  if (EncryptionKeyLength != 0)
    EncryptionKey = substr (data, 0, 7); # Allways 8 byte length
  else
    EncryptionKey = NULL;
 }

 session_set_server_max_size (size:MaxBufferSize);
 if (MaxBufferSize > (session_get_buffersize() - 0x100))
   session_set_buffersize(size:MaxBufferSize+0x100);

 ret = smb_session_setup_andx (session_key:SessionKey, dialect:DialectIndex, challenge:EncryptionKey, mode:SecurityMode, extended:Extended, login:login, password:password, domain:domain, host:host, realm:realm);

 if (isnull (ret))
   return 0;
 else 
   return 1;
}




#---------------------------------------------------------#
# Function    : smb_tree_connect_and_x                    #
# Description : Connects to a remote share                #
#---------------------------------------------------------#

function smb_tree_connect_and_x (share)
{
 local_var header, parameters, password, path, service, data, packet, ret, tid;

 header = smb_header (Command: SMB_COM_TREE_CONNECT_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
              raw_word (w:0xC) +
              raw_word (w:1); # strlen (password)
 
 parameters = smb_parameters (data:parameters);
 
 password = raw_string (0x00); # NULL password / To change for share authentication
 path = cstring (string:"\\", _null:1) + cstring (string:session_get_hostname(), _null:1) + cstring (string:"\", _null:1) + cstring (string:share);
 service = ascii (string:"?????");
 
 data = password +
        path +
	service;
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 # Some checks in the header first
 header = get_smb_header (smbblob:ret);
 if (!header)
   return NULL;

 tid = get_header_tid (header:header);
 session_set_tid (tid:tid);

 return ret;
}


#---------------------------------------------------------#
# Function    : smb_create_and_x                          #
# Description : Connects to a remote file                 #
#---------------------------------------------------------#

function smb_create_and_x (name, desired_access, flags_attributes, share_mode, create_disposition, create_options)
{
 local_var header, parameters, data, packet, ret, offset, fid, pad;

 header = smb_header (Command: SMB_COM_NT_CREATE_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 pad = NULL;
 if (session_is_unicode() == 1)
   pad = raw_byte (b:0);

 filename = cstring (string:name);

 parameters = raw_byte (b:255) + # no further command
              raw_byte (b:0) +
              raw_word (w:0) +
	      raw_byte (b:0) +
              raw_word (w:strlen(cstring(string:name,_null:1))) +
	      raw_dword (d:0x16)                +  # flags to change
	      raw_dword (d:0)                   +  # root fid
	      raw_dword (d:desired_access)      +  # access mask
	      raw_dword (d:0) + raw_dword (d:0) +  # allocation size
	      raw_dword (d:flags_attributes)    +  # file attributes
	      raw_dword (d:share_mode)          +  # share access
	      raw_dword (d:create_disposition)  +  # Disposition
	      raw_dword (d:create_options)      +  # create options
	      raw_dword (d:2)                   +  # impersonation
	      raw_byte  (b:3);                     # security flags
                     	      
 parameters = smb_parameters (data:parameters);
 
 data = pad + filename;
 
 data = smb_data (data:data);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 parameters = get_smb_parameters (smbblob:ret);
 if (!parameters || (strlen(parameters) < 63))
   return NULL;

 offset = get_word (blob:parameters, pos:2);

 ret = NULL;
 ret[0] = get_word (blob:parameters, pos:5); # FID
 ret[1] = substr (parameters, 55, 62);       # SIZE

 return ret;
}


#---------------------------------------------------------#
# Function    : smb_write_and_x                           #
# Description : writes to a remote pipe                   #
#---------------------------------------------------------#

function smb_write_and_x (fid, offset, mode, data)
{
 local_var header, parameters, dat, packet, ret, pad;

 pad = raw_byte (b:0);

 header = smb_header (Command: SMB_COM_WRITE_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 parameters = raw_byte (b:255) +            # no further command
              raw_byte (b:0) +              # reserved
              raw_word (w:0) +              # andxoffset
	      raw_word (w:fid) +            # fid
	      raw_dword (d:offset) +        # offset
              raw_dword (d:0xFFFFFFFF) +    # reserved
	      raw_word (w:mode) +           # write mode
	      raw_word (w:strlen (data)) +  # remaining
	      raw_word (w:0) +              # data length high
	      raw_word (w:strlen (data)) +  # data length low
	      raw_word (w:64) +             # data offset == 64
	      raw_dword (d:0) ;             # high offset
                    	      
 parameters = smb_parameters (data:parameters);
 
 dat = pad + data;
 
 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 return 1;
}



#---------------------------------------------------------#
# Function    : smb_read_and_x                            #
# Description : reads on a remote pipe                    #
#---------------------------------------------------------#

function smb_read_and_x (fid, offset, length)
{
 local_var header, parameters, data, packet, ret, pad, code;

 header = smb_header (Command: SMB_COM_READ_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 pad = raw_byte (b:0);

 parameters = raw_byte (b:255) +            # no further command
              raw_byte (b:0) +              # reserved
              raw_word (w:0) +              # andxoffset
	      raw_word (w:fid) +            # fid
	      raw_dword (d:offset) +        # offset
	      raw_word (w:length) +         # Max count low
	      raw_word (w:length) +         # Min count
	      raw_dword (d:0xFFFFFFFF) +    # Reserved or max count high ?
	      raw_word (w:length) +         # Remaining
              raw_dword (d:0) ;             # high offset
                    	      
 parameters = smb_parameters (data:parameters);
 
 data = pad + smb_data (data:NULL);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 header = get_smb_header (smbblob:ret);
 if (isnull (header))
   return NULL;

 code = get_header_nt_error_code(header);
 if ((code != STATUS_SUCCESS) && (code != STATUS_BUFFER_OVERFLOW))
   return NULL;

 data = get_smb_data (smbblob:ret);
 if (isnull (data))
   return NULL;

 data = substr (data, 1, strlen(data)-1);

 return data;
}



#---------------------------------------------------------#
# Function    : smb_trans_and_x                           #
# Description : TransAndX Request                         #
#---------------------------------------------------------#

function smb_trans_and_x (extra_parameters, transname, param, data, max_pcount)
{
 local_var header, parameters, dat, packet, ret, pad, trans, p_offset, d_offset, plen, dlen, elen, pad2;

 pad = pad2 = NULL;
 if (session_is_unicode () == 1)
   pad = raw_byte (b:0);
 else
   pad2 = raw_byte (b:0);

 header = smb_header (Command: SMB_COM_TRANSACTION,
                      Status: nt_status (Status: STATUS_SUCCESS));

 trans = cstring (string:transname);
 
 p_offset = 66 + strlen(trans) + strlen (extra_parameters);
 d_offset = p_offset + strlen (param);
 
 plen = strlen(param);
 dlen = strlen(data);
 elen = strlen(extra_parameters);

 parameters = raw_word (w:plen)            +   # total parameter count
	      raw_word (w:dlen) +   # total data count
	      raw_word (w:max_pcount)            +   # Max parameter count
	      raw_word (w:0xFFFF)         +   # Max data count
	      raw_byte (b:0)            +   # Max setup count
              raw_byte (b:0)            +   # Reserved
	      raw_word (w:0)            +   # Flags
	      raw_dword (d:0)           +   # Timeout
	      raw_word (w:0)            +   # Reserved
	      raw_word (w:plen)            +   # Parameter count
	      raw_word (w:p_offset)           +   # Parameter offset
	      raw_word (w:dlen) +   # Data count
	      raw_word (w:d_offset)           +   # Data offset
	      raw_byte (b:elen/2)            +   # Setup count
	      raw_byte (b:0);               # Reserved

 parameters += extra_parameters; 
 
 parameters = smb_parameters (data:parameters);
 
 dat = pad +
       trans +
       pad2 +
       raw_word (w:0) +
       param + 
       data;
 
 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 dat = get_smb_data (smbblob:ret);
 if (isnull (dat))
   return NULL;

 dat = substr (dat, 1, strlen(dat)-1);

 return dat;
}



#---------------------------------------------------------#
# Function    : smb_trans2                                #
# Description : Trans2 Request                            #
#---------------------------------------------------------#

function smb_trans2 (param, data, max_pcount, command)
{
 local_var header, parameters, dat, packet, ret, pad, trans, p_offset, d_offset, plen, dlen, elen;

 header = smb_header (Command: SMB_COM_TRANSACTION2,
                      Status: nt_status (Status: STATUS_SUCCESS));
 
 pad = raw_byte (b:0); 
 
 p_offset = 66;
 d_offset = p_offset + strlen (param);
 
 plen = strlen(param);
 dlen = strlen(data);

 parameters = raw_word (w:plen)         +   # total parameter count
	      raw_word (w:dlen)         +   # total data count
	      raw_word (w:max_pcount)   +   # Max parameter count
	      raw_word (w:1000)         +   # Max data count
	      raw_byte (b:0)            +   # Max setup count
              raw_byte (b:0)            +   # Reserved
	      raw_word (w:0)            +   # Flags
	      raw_dword (d:0)           +   # Timeout
	      raw_word (w:0)            +   # Reserved
	      raw_word (w:plen)         +   # Parameter count
	      raw_word (w:p_offset)     +   # Parameter offset
	      raw_word (w:dlen)         +   # Data count
	      raw_word (w:d_offset)     +   # Data offset
	      raw_byte (b:1)            +   # Setup count
	      raw_byte (b:0)            +   # Reserved
              raw_word (w:command);         # command

 parameters = smb_parameters (data:parameters);
 
 dat = pad +
       param + 
       data;
 
 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 dat = get_smb_data (smbblob:ret);
 if (isnull (dat))
   return NULL;

 dat = substr (dat, 1, strlen(dat)-1);

 return dat;
}


#---------------------------------------------------------#
# Function    : smb_nt_trans                              #
# Description : NT Trans Request                          #
#---------------------------------------------------------#

function smb_nt_trans (param, data, command, max_pcount, max_dcount)
{
 local_var header, parameters, dat, packet, ret, pad, trans, p_offset, d_offset, plen, dlen, elen;

 header = smb_header (Command: SMB_COM_NT_TRANSACT,
                      Status: nt_status (Status: STATUS_SUCCESS));
 
 pad = raw_byte (b:0) + raw_word(w:0); 
 
 p_offset = 76;
 d_offset = p_offset + strlen (param);
 
 plen = strlen(param);
 dlen = strlen(data);

 parameters = raw_byte (b:0)            +   # Max setup count
              raw_word (w:0)            +   # Reserved
	      raw_dword (d:plen)        +   # total parameter count
	      raw_dword (d:dlen)        +   # total data count
	      raw_dword (d:max_pcount)  +   # Max parameter count
	      raw_dword (d:max_dcount)  +   # Max data count
	      raw_dword (d:plen)        +   # Parameter count
	      raw_dword (d:p_offset)    +   # Parameter offset
	      raw_dword (d:dlen)        +   # Data count
	      raw_dword (d:d_offset)    +   # Data offset
	      raw_byte (b:0)            +   # Setup count
              raw_word (w:command);         # command

 parameters = smb_parameters (data:parameters);
 
 dat = pad +
       param + 
       data;
 
 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;

 dat = get_smb_data (smbblob:ret);
 if (isnull (dat))
   return NULL;

 dat = substr (dat, 1, strlen(dat)-1);

 return dat;
}


#---------------------------------------------------------#
# Function    : smb_trans_pipe                            #
# Description : TransAndX Pipe Request                    #
#---------------------------------------------------------#

function smb_trans_pipe (fid, data)
{
 local_var parameters, ret;

 parameters = raw_word (w:TRANS_PIPE) +
              raw_word (w:fid);

 return smb_trans_and_x (extra_parameters:parameters, transname:"\PIPE\", param:NULL, data:data, max_pcount:0);
}


#---------------------------------------------------------#
# Function    : smb_trans_lanman                          #
# Description : TransAndX LANMAN Request                  #
#---------------------------------------------------------#

function smb_trans_lanman (data)
{
 return smb_trans_and_x (extra_parameters:NULL, transname:"\PIPE\LANMAN", param:data, data:NULL, max_pcount:8);
}


#---------------------------------------------------------#
# Function    : smb_close                                 #
# Description : Close a pipe                              #
# Return      : 1 on success (else NULL)                  #
#---------------------------------------------------------#

function smb_close (fid)
{
 local_var header, parameters, data, packet, ret;

 header = smb_header (Command: SMB_COM_CLOSE,
                      Status: nt_status (Status: STATUS_SUCCESS));

 parameters = raw_word (w:fid)          +   # FID
              raw_dword (d:0xFFFFFFFF) ;    # Last write (not specified)

 parameters = smb_parameters (data:parameters);
 
 data = smb_data (data:NULL);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 return 1;
}


#---------------------------------------------------------#
# Function    : smb_logoff_andx                           #
# Description : Close a session                           #
# Return      : 1 on success (else NULL)                  #
#---------------------------------------------------------#

function smb_logoff_andx ()
{
 local_var header, parameters, data, packet, ret;

 header = smb_header (Command: SMB_COM_LOGOFF_ANDX,
                      Status: nt_status (Status: STATUS_SUCCESS));

 parameters = raw_byte (b:0xFF)         +   # No further command
              raw_byte (b:0)            +   # Reserved
              raw_word (w:0) ;              # AndXOffset

 parameters = smb_parameters (data:parameters);
 
 data = smb_data (data:NULL);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 return 1;
}


#---------------------------------------------------------#
# Function    : smb_tree_disconnect                       #
# Description : Close a tree                              #
# Return      : 1 on success (else NULL)                  #
#---------------------------------------------------------#

function smb_tree_disconnect ()
{
 local_var header, parameters, data, packet, ret, tid;

 tid = session_get_tid ();
 if (tid == 0)
   return 1;

 header = smb_header (Command: SMB_COM_TREE_DISCONNECT,
                      Status: nt_status (Status: STATUS_SUCCESS));

 parameters = smb_parameters (data:NULL);
 
 data = smb_data (data:NULL);

 packet = netbios_packet (header:header, parameters:parameters, data:data);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;
 
 if (smb_check_success (data:ret) == FALSE)
   return NULL;

 session_set_tid (tid:0);

 return 1;
}








#==================================================================#
# Section 5. DCE/RPC                                               #
#==================================================================#



function hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);	# remove trailing blanks, CR, LF...
 l = strlen(s);
 ret = NULL;
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
						    

function inverse (data)
{
 local_var tmp, i;
 
 tmp = NULL;
 for (i=strlen(data)-1; i >= 0; i--)
 {
  tmp += data[i];
 }

 return tmp;
}


function _hex (s)
{
 return inverse (data:hex2raw(s:s));
}


function encode_uuid (uuid)
{
 local_var tmp, encoded, val;

 encoded = NULL;
 
 tmp = split (uuid, sep:"-", keep:FALSE);
 
 encoded = _hex(s:tmp[0]) +
           _hex(s:tmp[1]) +
	   _hex(s:tmp[2]) +
	   hex2raw(s:tmp[3]) +
	   hex2raw(s:tmp[4]);

 return encoded;
}


function dce_rpc (type,cid,data)
{
 local_var packet;

 packet = raw_byte (b:5) +                # version
          raw_byte (b:0) +                # version (minor)
	  raw_byte (b:type) +             # packet type
	  raw_byte (b:3) +                # packet flags
	  raw_dword (d:16) +              # data representation (little-endian/ascii)
	  raw_word (w:16+strlen(data)) +  # Frag length
	  raw_word (w:0) +                # auth length
	  raw_dword (d:cid) +             # caller ID
	  data;
 
 return packet;
}


function dce_rpc_bind (cid, uuid, vers)
{
 local_var packet;
 
 packet = raw_word (w:4280) +       # Max Xmit Frag
          raw_word (w:4280) +       # Max recv Frag
	  raw_dword (d:0)   +       # Assoc group
	  raw_dword (d:1)   +       # Num context items
	  raw_word (w:0)    +       # Context ID
	  raw_word (w:1)    +       # num trans item
	  encode_uuid (uuid:uuid) + # Interface uuid
	  raw_word (w:vers)    +       # interface version
	  raw_word (w:0)    +       # interface version (minor)
	  encode_uuid (uuid:"8a885d04-1ceb-11c9-9fe8-08002b104860") +
	  raw_dword (d:2) ;         # syntax version

 return dce_rpc (type:DCE_RPC_BIND, cid:cid, data:packet);	  
}


function dce_rpc_parse_bind_ack (data)
{
 local_var len;

 if (strlen (data) < 26)
   return NULL;
 len = get_word (blob:data, pos:24);
 if ((len%2) == 0)
   len += 2; # 2 bytes padding

 if (strlen (data) < 26+len+4)
   return NULL;
 
 res = get_word (blob:data, pos:26+len+2);
 
 return res;
}


function dce_rpc_request (code, data)
{
 local_var packet;
 
 packet = raw_dword (d:strlen(data))  +       # Alloc hint
          raw_word (w:0)              +       # Context ID
	  raw_word (w:code)           +       # Opnum
          data;

 return dce_rpc (type:DCE_RPC_REQUEST, cid:session_get_cid(), data:packet);	  
}


function dce_rpc_parse_response (fid, data)
{
 local_var resp, flag, len, alloc, tmp, dat;

 if (strlen (data) < 24)
   return NULL;
   
 flag = get_byte (blob:data, pos:3);
 len = get_word (blob:data, pos:8) - 24;
 alloc = get_dword (blob:data, pos:16);

 if (strlen (data) < (24 + len))
   return NULL;
   
 resp = substr (data, 24, 24 + len - 1);

 # If it is not the last dce_rpc packet we continue to read
 while (!(flag & 2))
 {
  # we read only 1000 bytes at a time
  tmp = smb_read_and_x (fid:fid, offset:0, length:1024);
  if (strlen (tmp) < 24)
    return NULL;

  flag = get_byte (blob:tmp, pos:3);
  len = get_word (blob:tmp, pos:8);
  alloc = get_dword (blob:tmp, pos:16);

  while (strlen (tmp) < len)
  {
   dat = smb_read_and_x (fid:fid, offset:0, length:1024);
   if (!dat)
     return NULL;
   tmp += dat;
  }
  
  resp += substr (tmp, 24, 24 + len - 1);
 }

 return resp;
}



function bind_pipe (pipe, uuid, vers)
{
 local_var fid, ret, data;
 
 ret = smb_create_and_x (name:pipe,
                         desired_access:FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA |
                                        FILE_READ_EA | FILE_WRITE_EA | 
                                        FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                         flags_attributes:0,
                         share_mode:FILE_SHARE_READ | FILE_SHARE_WRITE,
                         create_disposition:OPEN_EXISTING,
                         create_options:0x40);
 if (isnull(ret))
   return NULL;
 
 fid = ret[0];

 ret = smb_write_and_x (fid:fid, offset:0, mode:WRITE_START, data:dce_rpc_bind(cid:session_get_cid(), uuid:uuid, vers:vers));
 if (isnull (ret) || (ret != 1))
   return NULL;

 data = smb_read_and_x (fid:fid, offset:0, length:1024);
 if (!data)
   return NULL;
 
 ret = dce_rpc_parse_bind_ack (data:data);
 if (isnull (ret) || (ret != 0))
   return NULL;

 return fid;
}



function buffer_parameter (ref_id, size)
{
 return raw_dword (d:ref_id) + raw_dword (d:size);
}


function class_parameter (ref_id, name, size, _null)
{
 local_var tmp, len;

 uni = session_is_unicode ();
 if (uni == 0)
   session_set_unicode (unicode:1);
 
 if (!isnull(_null) && (_null == FALSE))
   tmp = cstring (string:name, _null:1);
 else
   tmp = cstring (string:name);
 len = strlen (tmp);

 if ((len/2)%2 == 1)
   tmp += raw_word (w:0);

 if (!isnull (size))
   data = raw_word (w:len) + # length 
          raw_word (w:len);  # size
 else
   data = NULL;

 data += raw_dword (d:ref_id)     + # Referent ID
        raw_dword (d:len/2)      + # Max count
	raw_dword (d:0)          + # Offset
	raw_dword (d:len/2)      + # Actual Count
	tmp ;                      # name

 if (uni == 0)
   session_set_unicode (unicode:0); 
 return data;
}




function NetGetInfo (pipe, uuid, vers, level, opnum)
{
 local_var fid, data, rep, resp, info_level, info_struct, ret;

 fid = bind_pipe (pipe:pipe, uuid:uuid, vers:vers);

 data = class_parameter (ref_id:0x00020000, name:"\\" + session_get_hostname ()) +

	raw_dword (d:level) ;      # Info level

 data = smb_trans_pipe (fid:fid, data:dce_rpc_request (code:opnum, data:data));
 if (!data)
 {
   smb_close (fid:fid);
   return NULL;
 }

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) < 8))
 {
  smb_close (fid:fid);
  return NULL;
 }
 
 info_level = get_dword (blob:rep, pos:0);
 info_struct = substr (rep, 4, strlen(rep) - 5);

 resp = get_dword (blob:rep, pos:strlen(rep) - 4);
 if (resp != STATUS_SUCCESS)
 {
  smb_close (fid:fid);
  return NULL;
 }

 ret = NULL;
 ret[0] = info_level;
 ret[1] = info_struct;

 smb_close (fid:fid);
 
 return ret;
}


function NetEnum (pipe, level, uuid, vers, opnum)
{
 local_var fid, name, len, data, rep, resp, ret;

 fid = bind_pipe (pipe:pipe, uuid:uuid, vers:vers);

 data = class_parameter (ref_id:0x00020000, name:"\"+session_get_hostname()) +

	raw_dword (d:level)      + # Info level
        
        # share info container
        raw_dword (d:level)      + # Share Info level (multi share request with different level ?)
        raw_dword (d:0x00020004) + # Referent ID
        raw_dword (d:0)          + # number of entries
        raw_dword (d:0)          + # share info array (NULL)

        raw_dword (d:0xFFFFFFFF) + # preferred length
        
        # Enum handle
        buffer_parameter (ref_id:0x00020008, size:0);

 data = smb_trans_pipe (fid:fid, data:dce_rpc_request (code:opnum, data:data));
 if (!data)
 {
   smb_close (fid:fid);
   return NULL;
 }

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) < 24))
 {
  smb_close (fid:fid);
  return NULL;
 }

 resp = get_dword (blob:rep, pos:strlen(rep) - 4);
 if (resp != STATUS_SUCCESS)
 {
  smb_close (fid:fid);
  return NULL;
 }

 ret = substr (rep, 0, strlen(rep)-4-1);

 smb_close (fid:fid);
 
 return ret;
}


function get_sid (blob, pos)
{
 local_var count, len;

 if (strlen(blob) < pos + 8)
   return NULL;

 count = ord(blob[pos+1]);
 len = 8 + count*4;

 if (strlen(blob) < pos + len)
   return NULL;

 return substr (blob, pos, pos+len-1);
}


function sid2string (sid)
{
 local_var ret, num, val;

 ret = NULL;
 if (strlen(sid) < 8)
   return NULL;

 val = get_byte (blob:sid, pos:0); 
 ret += string (val, "-");
 num = get_byte(blob:sid, pos:1);
 val = get_byte(blob:sid, pos:7);
 ret += string (val, "-");

 if (strlen(sid) < 8 + num*4)
   return NULL;

 for (i=0; i<num; i++)
 {
  val = get_dword (blob:sid, pos:8+i*4);
  ret += string (val,"-");
 }

 return substr (ret,0,strlen(ret)-2); 
}

function parse_dacl (blob)
{
 local_var dacl, size, access_rigths, sid;

 if (strlen (blob) < 8)
   return NULL;

 dacl = NULL;

 access_rights = get_dword (blob:blob, pos:4);
 size = get_word (blob:blob, pos:2); # size + 1 

 if (strlen(blob) != (size - 1))
   return NULL;

 sid = substr (blob, 8, size-1);

 dacl[0] = access_rights;
 dacl[1] = sid;

 return dacl; 
}


function parse_pdacl (blob)
{
 local_var rev, size, nsid, i, pos, pdacl, length;

 if (strlen (blob) < 8)
   return NULL;

 rev = get_word (blob:blob, pos:0);
 size = get_word (blob:blob, pos:2);
 nsid = get_dword (blob:blob, pos:4);

 pos = 8;

 if (strlen (blob) < size)
   return NULL;

 pdacl = NULL;
 for (i=0; i<nsid; i++)
 {
  if (strlen(blob) < pos + 8)
    return NULL;

  length = get_word (blob:blob, pos:pos+2);
  if (strlen(blob) < pos+length)
    return NULL;

  pdacl[i] = substr (blob, pos, pos+length-2);  # length = real length + 1 ??
 
  pos += length;
 }

 return pdacl;
}


function parse_security_descriptor (blob)
{
 local_var rev, sbz1, sec_control, size, pos, security_descriptor;
 local_var psid_owner, psid_group, psid_sacl, psid_dacl;
 local_var sid_owner, sid_group, sacl, dacl;

 sid_owner = sid_group = sacl = dacl = NULL;

 if (strlen (blob) < 20)
   return NULL;

 rev = get_byte (blob:blob, pos:0);
 sbz1 = get_byte (blob:blo, pos:1);
 sec_control = get_word (blob:blob, pos:2);

 psid_owner = get_dword (blob:blob, pos:4);
 psid_group = get_dword (blob:blob, pos:8);
 pacl_sacl = get_dword (blob:blob, pos:12);
 pacl_dacl = get_dword (blob:blob, pos:16);

 if (pacl_sacl != 0)
 {
  pos = pacl_sacl;
  if (strlen(blob) < pos + 4)
    return NULL;

  rev = get_word (blob:blob, pos:pos);
  size = get_word (blob:blob, pos:pos+2);

  if (strlen(blob) < pos + size)
    return NULL;

  sacl = substr (blob, pos, pos+size-1);
 }

 if (pacl_dacl != 0)
 {
  pos = pacl_dacl;
  if (strlen(blob) < pos + 4)
    return NULL;

  rev = get_word (blob:blob, pos:pos);
  size = get_word (blob:blob, pos:pos+2);

  if (strlen(blob) < pos + size)
    return NULL;

  dacl = substr (blob, pos, pos+size-1);
 }

 if (psid_owner != 0)
 {
  pos = psid_owner;
  sid_owner = get_sid (blob:blob, pos:pos);
  if (!sid_owner)
    return NULL;
 }
 
 if (psid_group != 0)
 {
  pos = psid_group;
  sid_group = get_sid (blob:blob, pos:pos);
  if (!sid_group)
    return NULL;
 }

 security_descriptor = NULL;
 security_descriptor[0] = sid_owner;
 security_descriptor[1] = sid_group;
 security_descriptor[2] = sacl;
 security_descriptor[3] = dacl;

 return security_descriptor;
}





#==================================================================#
# Section 6a. SAM API                                              #
#==================================================================#


#---------------------------------------------------------#
# Function    : SamConnect2                               #
# Description : Connects to the remote SAM pipe.          #
# Return      : ret[0] : registry handle                  #
#               ret[1] : registry pipe                    #
#               ret[2] : 1 (Pipe handle)                  #
#---------------------------------------------------------#

function SamConnect2 ()
{
 local_var fid, ret, data, resp, rep;

 fid = bind_pipe (pipe:"\samr", uuid:"12345778-1234-abcd-ef00-0123456789ac", vers:1);
 if (isnull (fid))
   return NULL;

 data = class_parameter (ref_id:0x00020000, name:"\"+session_get_hostname()) +
        raw_dword (d:0x30)        ; # Access mask

 data = smb_trans_pipe (fid:fid, data:dce_rpc_request (code:OPNUM_SAMCONNECT2, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = fid;
 ret[2] = 1;

 return ret;
}


#---------------------------------------------------------#
# Function    : SamEnumerateDomainsInSamServer            #
# Description : Name is explicit enough                   #
# Return      : Array of Domain Names                     #
#---------------------------------------------------------#

function SamEnumerateDomainsInSamServer (handle)
{
 local_var data, resp, rep, ret, len, ref_id, count;
 local_var actual_count, max_count, offset, name, pos, i;

 data = handle[0]                     +  # Handle
	raw_dword (d:0)               +  # NULL handle
	raw_dword (d:0xFFFFFFFF) ;       # Max buf size
        
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMENUMDOM, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 handle = get_dword (blob:rep, pos:0);
 ref_id = get_dword (blob:rep, pos:4);
 count = get_dword (blob:rep, pos:8);
 ref_id = get_dword (blob:rep, pos:12);
 max_count = get_dword (blob:rep, pos:16);

 # we don't care about size and ref_id
 pos = count * 12 + 20;

 ret = NULL;

 for (i=0; i<count; i++)
 {
  if (strlen (rep) < pos + 12)
    return NULL;

  max_count = get_dword (blob:rep, pos:pos);
  offset = get_dword (blob:rep, pos:pos+4);
  actual_count = get_dword (blob:rep, pos:pos+8);

  if (session_is_unicode() == 1)
    actual_count = actual_count * 2;

  if (strlen(rep) < pos + 12 + actual_count)
    return NULL;

  name = get_string2 (blob:rep, pos:pos + 12, len:actual_count);
  
  pos += actual_count + 12;

  while ((actual_count % 4) != 0)
  {
   actual_count ++;
   pos ++;
  }

  ret[i] = name;
 }
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamLookupDomainInSamServer                #
# Description : Name is explicit enough                   #
# Return      : Domain SID                                #
#---------------------------------------------------------#

function SamLookupDomainInSamServer (handle, domain)
{
 local_var data, resp, rep;

 data = handle[0]                     +  # Handle
	class_parameter (ref_id:0x00020000, name:domain, size:TRUE, _null:FALSE);
        
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMLOOKUP, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 36))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;
 
 return substr(rep, 8, strlen(rep)-5);
}


#---------------------------------------------------------#
# Function    : SamOpenDomain                             #
# Description : Open the given domain sid                 #
# Return      : ret[0] domain handle                      #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function SamOpenDomain (handle, sid, access)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:access)          +  # Access mask
        raw_dword (d:ord(sid[1]))     +  # count
        sid ;                            # sid

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMOPENDOM, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = handle[1];
 ret[2] = 0;
 
 return ret;
}



#---------------------------------------------------------#
# Function    : SamLookupNamesInDomain                    #
# Description : search user in domain                     #
# Return      : user rid                                  #
#                                                         #
# Note        : Support only one name (not array)         #
#---------------------------------------------------------#

function SamLookupNamesInDomain (handle, user)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:1)               +  # count
        raw_dword (d:1000)            +  # max count
        raw_dword (d:0)               +  # offset
        raw_dword (d:1)               +  # actual count
	class_parameter (ref_id:0x00020000, name:user, size:TRUE, _null:FALSE);        

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMLOOKUPNAME, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 36))
   return NULL;
 
 resp = get_dword (blob:rep, pos:32);
 if (resp != STATUS_SUCCESS)
   return NULL;

 return get_dword (blob:rep, pos:12);
}


#---------------------------------------------------------#
# Function    : SamOpen                                   #
# Description : Open the given rid                        #
# Return      : ret[0] handle                             #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function SamOpen (handle, rid, access, code)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:access)          +  # Access mask
        raw_dword (d:rid)             ;  # count

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:code, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = handle[1];
 ret[2] = 0;
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamOpenUser                               #
# Description : Open the given user rid                   #
# Return      : ret[0] user handle                        #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function SamOpenUser (handle, rid, access)
{
 return SamOpen (handle:handle, rid:rid, access:access, code:OPNUM_SAMOPENUSER);
}


#---------------------------------------------------------#
# Function    : SamOpenGroup                              #
# Description : Open the given group rid                  #
# Return      : ret[0] group handle                       #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function SamOpenGroup (handle, rid, access)
{
 return SamOpen (handle:handle, rid:rid, access:access, code:OPNUM_SAMOPENGROUP);
}


#---------------------------------------------------------#
# Function    : SamOpenAlias                              #
# Description : Open the given alias                      #
# Return      : ret[0] alias handle                       #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function SamOpenAlias (handle, rid, access)
{
 local_var data, resp, rep, ret, len;

 data = handle[0]                     +  # Handle
        raw_dword (d:access)          +  # Access mask
        raw_dword (d:rid)             ;  # count

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMOPENALIAS, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = handle[1];
 ret[2] = 0;
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamGetGroupsForUser                       #
# Description : return user groups                        #
# Return      : array of rid                              #
#---------------------------------------------------------#

function SamGetGroupsForUser (handle)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count;

 data = handle[0] ;

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMGETGROUPS, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 count  = get_dword (blob:rep, pos:4);
 ref_id = get_dword (blob:rep, pos:8);
 max_count = get_dword (blob:rep, pos:12);

 pos = 16;

 if (strlen(rep) < pos + count * 8 + 4)
   return NULL;

 ret = NULL;
 for (i=0; i<count; i++)
 {
  ret[i] = get_dword (blob:rep, pos:pos);
  pos += 8;
 }
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamGetMembersInAlias                      #
# Description : return members                            #
# Return      : array of rid                              #
#---------------------------------------------------------#

function SamGetMembersInAlias (handle)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count, num;

 data = handle[0] ;

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMGETMEMALIAS, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 count  = get_dword (blob:rep, pos:0);
 ref_id = get_dword (blob:rep, pos:4);
 max_count = get_dword (blob:rep, pos:8);

 # we don't care about ref_id
 pos = 12 + count * 4;

 if (strlen(rep) < pos + 4)
   return NULL;

 ret = NULL;
 for (i=0; i<count; i++)
 {
  if (strlen(rep) < pos+12)
    return NULL;

  num = get_dword (blob:rep, pos:pos);
  if (strlen(rep) < pos+12+num*4)
    return NULL;

  ret[i] = substr(rep, pos+4, pos+12+num*4-1);
  pos += 12 + num*4;
 }
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamGetMembersInGroup                      #
# Description : return members                            #
# Return      : array of rid                              #
#---------------------------------------------------------#

function SamGetMembersInGroup (handle)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count, num;

 data = handle[0] ;

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMGETMEMGROUP, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 count  = get_dword (blob:rep, pos:4);
 pos = 20;

 if (strlen(rep) < pos + count*4 + 4)
   return NULL;

 ret = NULL;
 for (i=0; i<count; i++)
 {
  ret[i] = get_dword (blob:rep, pos:pos);
  pos += 4;
 }
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamLookupIdsInDomain                      #
# Description : return ids names                          #
# Return      : array of names                            #
#---------------------------------------------------------#

function SamLookupIdsInDomain (handle, ids)
{
 local_var data, resp, rep, ret, len, i, pos, ref_id, count, max_count, actual_count, offset;

 data = handle[0]                    +
        raw_dword (d:max_index(ids)) + # count
        raw_dword (d:1000)           + # max_count
        raw_dword (d:0)              + # offset
        raw_dword (d:max_index(ids)) ; # actual count

 foreach id (ids)
   data += raw_dword (d:id);

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMLOOKUPIDS, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 count = get_dword (blob:rep, pos:0);
 ref_id = get_dword (blob:rep, pos:4);
 max_count = get_dword (blob:rep, pos:8);

 # we don't care about size and ref_id
 pos = count * 8 + 12;

 ret = NULL;

 for (i=0; i<count; i++)
 {
  if (strlen (rep) < pos + 12)
    return NULL;

  max_count = get_dword (blob:rep, pos:pos);
  offset = get_dword (blob:rep, pos:pos+4);
  actual_count = get_dword (blob:rep, pos:pos+8);

  if (session_is_unicode() == 1)
    actual_count = actual_count * 2;

  if (strlen(rep) < pos + 12 + actual_count)
    return NULL;

  name = get_string2 (blob:rep, pos:pos + 12, len:actual_count);
  
  pos += actual_count + 12;

  while ((actual_count % 4) != 0)
  {
   actual_count ++;
   pos ++;
  }

  ret[i] = name;
 }
 
 return ret;
}


#---------------------------------------------------------#
# Function    : SamQueryInformationUser                   #
# Description : return user information                   #
# Return      : array of information  (level 21)          #
# Note        : Incomplete !!!                            #
#---------------------------------------------------------#

function SamQueryInformationUser (handle)
{
 local_var data, resp, rep, ret, pos, ref_id, level;

 data = handle[0]       +
        raw_word (w:21) ; # level

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMQUERYINFOU, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 52))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 level = get_dword (blob:rep, pos:4);
 
 pos = 8;

 ret = NULL;
 ret[0] = substr(rep, pos, pos+7);     # last logon time
 ret[1] = substr(rep, pos+8, pos+15);  # last logoff time
 ret[2] = substr(rep, pos+16, pos+23); # pwd last set
 ret[3] = substr(rep, pos+24, pos+31); # acct expiry
 ret[4] = substr(rep, pos+32, pos+39); # pwd can change
 ret[5] = substr(rep, pos+40, pos+47); # pwd must change

 # we don't care about name info (maybe later)
 pos = pos + 20*8   # time + string
           + 8 ;    # RID + GRID
 
 if (strlen(rep) < pos + 4)
   return NULL;

 ret[6] = get_dword (blob:rep, pos:pos);

 return ret;
}



#---------------------------------------------------------#
# Function    : SamQueryInformationDomain                 #
# Description : return domain information                 #
# Return      : array of information  (level 1,3 or 12)   #
# Note        : Incomplete !!!                            #
#---------------------------------------------------------#

function SamQueryInformationDomain (handle, level)
{
 local_var data, resp, rep, ret, pos, ref_id, lev;

 data = handle[0]       +
        raw_word (w:level) ; # level

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMQUERYINFOD, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 8))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep-4));
 if (resp != STATUS_SUCCESS)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 lev = get_word (blob:rep, pos:4);
 
 pos = 8;

 ret = NULL;

 if (lev == 1)
 {
  if (strlen(rep) != 36)
    return NULL;

  ret[0] = get_word (blob:rep, pos:pos);   # min pass len
  ret[1] = get_word (blob:rep, pos:pos+2); # pass history len
  # padding: 4 bytes
  ret[2] = convert_time_to_sec(time:substr (rep, pos+8, pos+15));    # max pass age
  ret[3] = convert_time_to_sec(time:substr (rep, pos+16, pos+23));   # min pass age
 }
 else if (lev == 3)
 {
  if (strlen(rep) != 20)
    return NULL;
  
  ret[0] = convert_time_to_sec(time:substr(rep, pos, pos+7));     # force logoff
 }
 else if (lev == 12)
 {
  if (strlen(rep) != 32)
    return NULL;
  
  ret[0] = convert_time_to_sec(time:substr (rep, pos, pos+7));        # lockout duration
  ret[1] = convert_time_to_sec(time:substr (rep, pos+8, pos+15));     # lockout duration
  ret[2] = get_word (blob:rep, pos:pos+16); # lockout threshold
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : SamGetAliasMemberShip                     #
# Description : return aliases                            #
#---------------------------------------------------------#

function SamGetAliasMemberShip (handle, sid, rids, urid)
{
 local_var data, resp, rep, ret, i, tmp_sid, count, num_sid, ref_id, rid, pos;

 tmp_sid = sid[0] + raw_byte(b:ord(sid[1]) + 1) + substr (sid, 2, strlen(sid)-1);
 count = ord(sid[1]) + 1;

 num_id = max_index(rids) + 1;

 data = handle[0]       +
        raw_dword (d:num_id)      + # count
        raw_dword (d:0x00146668)  + # ref_id
        raw_dword (d:num_id)      ; # max count

 ref_id = 0x001466a8;

 for (i=0; i<num_id; i++)
 {
  data += raw_dword (d:ref_id);
  ref_id += 0x28;
 }

 # we add user rid first
 data += raw_dword (d:count) + tmp_sid + raw_dword (d:urid);

 # and group rids
 foreach rid (rids)
   data += raw_dword (d:count) + tmp_sid + raw_dword (d:rid);

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMGETALIASM, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 12))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 count = get_dword (blob:rep, pos:0);
 if (count == 0)
   return NULL;

 ret = NULL;
 pos = 12;

 if (strlen(rep) < pos + count*4 + 4)
   return NULL;

 for (i=0; i<count; i++)
 {
  ret[i] = get_dword(blob:rep, pos:pos);
  pos += 4;
 }

 return ret;  
}


#---------------------------------------------------------#
# Function    : SamCloseHandle                            #
# Description : Close Handle                              #
#---------------------------------------------------------#

function SamCloseHandle (handle)
{
 local_var data, rep, code, ret;

 code = NULL;
 
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SAMCLOSEHANDLE, data:handle[0]));
 if (data)
 {
  rep = dce_rpc_parse_response (fid:handle[1], data:data);
  if (rep && (strlen (rep) == 24))
  { 
   # NULL handle (useless) + code
   # Return code
   code = get_dword (blob:rep, pos:20);
  }
 }

 if (handle[2] == 1)
   ret = smb_close (fid:handle[1]);
 
 if (isnull (code) || (code != STATUS_SUCCES) || (ret != 1))
   return NULL;
 
 return 1;
}




#==================================================================#
# Section 6b. Network Management API                               #
#==================================================================#



#---------------------------------------------------------#
# Function    : NetUseAdd                                 #
# Description : Connects to the remote share.             #
#               If no share is specified authenticates    #
#               for futur use (anonymous if no login)     #
# Return      : Return 1 on success                       #
#                     -1 if login failed                  #
#                      0 if share connection failed       #
#---------------------------------------------------------#

function NetUseAdd (login,password,domain,share)
{
 local_var ret;

 if (!session_is_authenticated ())
 {
  if (netbios_session_request () != TRUE)
   return -1;

  if (smb_login (login:login, password:password, domain:domain) != 1)
    return -1;
  else
    session_set_authenticated();
 }
 
 if (!isnull (share))
 {
  ret = smb_tree_connect_and_x (share:share);
  if (!ret)
    return 0;
 }

 return 1;
}



#---------------------------------------------------------#
# Function    : NetUseDel                                 #
# Description : Delete connection to the remote share.    #
# Optional    : close. If close == TRUE or not specified  #
#                      logoff and close socket            # 
#---------------------------------------------------------#

function NetUseDel (close)
{
 if (smb_tree_disconnect () != 1)
   return -1;

 if (isnull(close) || (close == TRUE))
 {
   if (session_is_authenticated ())
   {
    smb_logoff_andx ();
   }
   close (session_get_socket());
 }

 return 1;
}


#---------------------------------------------------------#
# Function    : NetServerGetInfo                          #
# Description : Return host information                   #
#---------------------------------------------------------#

function NetServerGetInfo (level)
{
 return NetGetInfo (pipe:"\srvsvc", uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3, level:level, opnum:OPNUM_SERVERGETINFO);
}



#---------------------------------------------------------#
# Function    : NetWkstaGetInfo                           #
# Description : Return workstation information            #
# Return      : array of level info                       #
#               [0] = platform_id (DWORD)                 #
#               [1] = hostname (STRING)                   #
#               [2] = domainname (STRING)                 #
#               [3] = major (DWORD)                       #
#               [4] = minor (DWORD)                       #
#               [5] = lanroot (STRING) - level 101-102    #
#               [6] = logged users (DWORD) - level 102    #
#---------------------------------------------------------#

function NetWkstaGetInfo (level)
{
 local_var ret, level, ref_id, rep, platform_id, major, minor, pos, logged, hostname, domainname, lanrootname, actual_count;

 ret = NetGetInfo(pipe:"\wkssvc", uuid:"6bffd098-a112-3610-9833-46c3f87e345a", vers:1, level:level, OPNUM_WKSTAGETINFO);
 if (isnull(ret))
   return NULL;

 level = ret[0];
 rep = ret[1];

 if ((level != 100) && (level != 101) && (level != 102))
   return NULL;

 if (strlen(rep) < 24)
   return NULL;

 ref_id = get_dword (blob:rep, pos:0);
 platform_id = get_dword (blob:rep, pos:4);
 # server_id = get_dword (blob:rep, pos:8);
 # host_id = get_dword (blob:rep, pos:12);
 major = get_dword (blob:rep, pos:16);
 minor = get_dword (blob:rep, pos:20);
 pos = 24;
 if (level >= 101)
 {
  # lan_id = get_dword (blob:rep, pos:pos);
  pos += 4;
 }
 if (level == 102)
 {
  if (strlen(rep) < 36)
    return NULL;
  logged = get_dword (blob:rep, pos:pos);
  pos += 4;
 }

 # Wksta is unicode

 # hostname
 if (strlen(rep) < pos + 12 + 4)
   return NULL;
 actual_count = get_dword(blob:rep, pos:pos+8) * 2;
 if (strlen(rep) < pos + actual_count + 4)
   return NULL;
 hostname = get_string2 (blob:rep, pos:pos+12, len:actual_count, _type:UNICODE_STRING);
 pos += actual_count + 12;
 if (actual_count%4)
   pos += 2;

 # Domain name
 if (strlen(rep) < pos + 12 + 4)
   return NULL;
 actual_count = get_dword(blob:rep, pos:pos+8) * 2;
 if (strlen(rep) < pos + actual_count + 4)
   return NULL;
 domainname = get_string2 (blob:rep, pos:pos+12, len:actual_count, _type:UNICODE_STRING);
 pos += actual_count + 12;
 if (actual_count%4)
   pos += 2;

 if (level >= 101)
 {
  # Lan root
  if (strlen(rep) < pos + 12 + 4)
    return NULL;
  actual_count = get_dword(blob:rep, pos:pos+8) * 2;
  if (strlen(rep) < pos + actual_count + 4)
    return NULL;
  lanrootname = get_string2 (blob:rep, pos:pos+12, len:actual_count, _type:UNICODE_STRING);
  pos += actual_count + 12;
  if (actual_count%4)
    pos += 2;
 }

 ret = NULL;
 ret[0] = platform_id;
 ret[1] = hostname;
 ret[2] = domainname;
 ret[3] = major;
 ret[4] = minor;
 if (level >= 101)
   ret[5] = lanrootname;
 if (level == 102)
   ret[6] = logged;

 return ret;
}


#---------------------------------------------------------#
# Function    : NetSessionEnum                            #
# Description : Return session information                #
#---------------------------------------------------------#

function NetSessionEnum (level, computer, user)
{
 local_var fid, name, len, data, rep, resp, ret, comp, _user;

 if (!isnull(computer))
  comp = class_parameter (ref_id:0x00020004, name:computer);
 else
  comp = raw_dword (d:0);

 if (!isnull(user))
  _user = class_parameter (ref_id:0x00020008, name:user);
 else
  _user = raw_dword (d:0);
   

 fid = bind_pipe (pipe:"\srvsvc", uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3);

 data = class_parameter (ref_id:0x00020000, name:"\"+session_get_hostname()) +
        comp                     + # computer name
        _user                    + # user name
	raw_dword (d:level)      + # Info level
        
        # share info container
        raw_dword (d:level)      + # Share Info level (multi share request with different level ?)
        raw_dword (d:0x00020004) + # Referent ID
        raw_dword (d:0)          + # number of entries
        raw_dword (d:0)          + # share info array (NULL)

        raw_dword (d:0xFFFFFFFF) + # preferred length
        
        # Enum handle
        buffer_parameter (ref_id:0x00020008, size:0);

 data = smb_trans_pipe (fid:fid, data:dce_rpc_request (code:OPNUM_NETSESSENUM, data:data));
 if (!data)
 {
   smb_close (fid:fid);
   return NULL;
 }

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) < 24))
 {
  smb_close (fid:fid);
  return NULL;
 }

 resp = get_dword (blob:rep, pos:strlen(rep) - 4);
 if (resp != STATUS_SUCCESS)
 {
  smb_close (fid:fid);
  return NULL;
 }

 ret = substr (rep, 0, strlen(rep)-4-1);

 smb_close (fid:fid);
 
 return ret;
}


#---------------------------------------------------------#
# Function    : NetShareEnum                              #
# Description : Return host's shares information          #
# level       : SHARE_INFO_x (x = 0, 1, 2, 502)           #
#---------------------------------------------------------#

function NetShareEnum (level)
{
 local_var rep, info_level, ref_id, num, max_count, actual_count, name, pos, shares, i;

 rep = NetEnum (pipe:"\srvsvc", uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3, level:level, opnum:OPNUM_SHAREENUM);
 if (!rep || (strlen (rep) < 24))
   return NULL;

 shares = NULL;

 info_level = get_dword (blob:rep, pos:0);
 
 if (info_level == SHARE_INFO_0)
 {
  info_level = get_dword (blob:rep, pos:4);
  ref_id = get_dword (blob:rep, pos:8);
  num = get_dword (blob:rep, pos:12);

  #SHARE_INFO_0 Array
  ref_id = get_dword (blob:rep, pos:16);
  max_count = get_dword (blob:rep, pos:20);

  # don't parse each share ref_id
  pos = 24 + max_count*4;

  for (i = 0; i<num; i++)
  {
   if (strlen (rep) < pos + 12)
     return NULL;

   max_count = get_dword (blob:rep, pos:pos);
   offset = get_dword (blob:rep, pos:pos+4);
   actual_count = get_dword (blob:rep, pos:pos+8);
  
   if (session_is_unicode () == 1)
     actual_count = actual_count * 2;

   if (strlen (rep) < pos + 12 + actual_count)
     return NULL;

   name = get_string2 (blob:rep, pos:pos + 12, len:actual_count);
  
   pos += actual_count + 12;

   while ((actual_count % 4) != 0)
   {
    actual_count ++;
    pos ++;
   }

   shares[i] = name;
  }
 }

 return shares;
}



#---------------------------------------------------------#
# Function    : NetWkstaUserEnum                          #
# Description : Return logged users                       #
# level       : WKSTA_USER_INFO_x (x = 0, 1)              #
#---------------------------------------------------------#

function NetWkstaUserEnum (level)
{
 return NetEnum (pipe:"\wkssvc", uuid:"6bffd098-a112-3610-9833-46c3f87e345a", vers:1, level:level, opnum:OPNUM_WKSTAUSERENUM);
}



#---------------------------------------------------------#
# Function    : NetServerEnum                             #
# Description : Return enumerated systems                 #
# Return      : return Array                              #
#---------------------------------------------------------#
#                                                         #
# If level == 0, array item is an ascii string.           #
#                                                         #
# If level == 1, array item is the following structure    #
#                                                         #
#   byte [16] server name                                 #
#   byte os_vers_major                                    #
#   byte os_vers_minor                                    #
#   DWORD server_type                                     #
#   byte [] comment (not null terminated)                 #
#                                                         #
#---------------------------------------------------------#

function NetServerEnum (level)
{
 local_var data, resp, convert, count, available, ret, i;

 data = raw_word (w:104)         + # Function code
        ascii (string:"WrLehDO") + # Parameter Descriptor
	ascii (string:"B16BBDz") + # Return Descriptor
	raw_word (w:level)       + # Detail level
	raw_word (w:0xFFFF)      + # Receive buffer length
	raw_dword (d:3) ;          # Server type (server + workstation)

 data = smb_trans_lanman (data:data);
 if (!data || (strlen(data) < 8))
   return NULL;

 # WORD status
 # WORD convert
 # WORD Entry count
 # WORD Available entries

 resp = get_word (blob:data, pos:0);
 convert = get_word (blob:data, pos:2);
 count = get_word (blob:data, pos:4);
 available = get_word (blob:data, pos:6);

 if (resp != STATUS_SUCCESS)
   return NULL;

 if (level == 0)
 {
  # struct :
  # byte [16] server_name;

  if (strlen (data) < (8 + count*16))
    return NULL;
  ret = NULL;
  for (i=0; i<count; i++)
  {
   ret[i] = get_string (blob:data, pos:8+i*16, _type:ASCII_STRING);
  }
 }
 else
 {
  # struct :
  # byte [16] server name
  # byte os_vers_major
  # byte os_vers_minor
  # DWORD server_type
  # DWORD comment_offset

  if (strlen (data) < (8 + count*26))
    return NULL;
  ret = NULL;
  for (i=0; i<count; i++)
  {
   # offset is a negative position at the end of the buffer
   offset = 65535 - get_dword (blob:data, pos:8+i*26+22);
   offset = strlen(data) - offset - 1;
   if ((offset > 0) && (offset < strlen(data)))
     comment = get_string (blob:data, pos:offset, _type:ASCII_STRING);
   else
     comment = "";
   ret[i] = substr (data, 8+i*26, 8+i*26+25) + comment;
  }  
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetGroups                          #
# Description : Return user's group                       #
#---------------------------------------------------------#

function NetUserGetGroups (user)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle, rids;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x200);
    if (!isnull (handle2))
    {
     rid = SamLookupNamesInDomain (handle:handle2, user:user);
     if (!isnull(rid))
     {
      uhandle = SamOpenUser (handle:handle2, rid:rid, access:0x100);
      if (!isnull(uhandle))
      {
       rids = SamGetGroupsForUser (handle:uhandle);
       if (!isnull (rids))
       #  ret = SamLookupIdsInDomain (handle:handle2, ids:rids);
         ret = rids;

       SamCloseHandle(handle:uhandle);
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }

  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetLocalGroups                     #
# Description : Return user's local group                 #
#---------------------------------------------------------#

function NetUserGetLocalGroups (user)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle, rids;

 builtsid = raw_string (0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00);
 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x280);
    if (!isnull (handle2))
    {
     handle3 = SamOpenDomain (handle:handle, sid:builtsid, access:0x280);
     if (!isnull (handle3))
     {
      rid = SamLookupNamesInDomain (handle:handle2, user:user);
      if (!isnull(rid))
      {
       uhandle = SamOpenUser (handle:handle2, rid:rid, access:0x100);
       if (!isnull(uhandle))
       {
        rids = SamGetGroupsForUser (handle:uhandle);
        if (!isnull (rids))
        {
          aliases = SamGetAliasMemberShip (handle:handle2, sid:sid, rids:rids, urid:rid);
          if (isnull(aliases))
            aliases = SamGetAliasMemberShip (handle:handle3, sid:sid, rids:rids, urid:rid);

          if (!isnull(aliases))
          #  ret = SamLookupIdsInDomain (handle:handle2, ids:rids);
          ret = aliases;
        }

        SamCloseHandle(handle:uhandle);
       }
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }

  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetLocalGroupGetMembers                   #
# Description : Return local group members                #
#---------------------------------------------------------#

function NetLocalGroupGetMembers (group)
{
 local_var ret, handle, domains, sid, handle2, rid, handle3, names, lsa;

 builtsid = raw_string (0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00);
 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  handle2 = SamOpenDomain (handle:handle, sid:builtsid, access:0x200);
  if (!isnull (handle2))
  {
   rid = SamLookupNamesInDomain (handle:handle2, user:group);
   if (!isnull(rid))
   {
    handle3 = SamOpenAlias (handle:handle2, rid:rid, access:0x2000C);
    if (!isnull(handle3))
    {
     members = SamGetMembersInAlias (handle:handle3);
     if (!isnull(members))
     {
      lsa = LsaOpenPolicy (desired_access:0x20801);
      if (!isnull(lsa))
      {
       names = LsaLookupSid (handle:lsa, sid_array:members);
       if (!isnull(names))
       {
        ret = names;
       }

       LsaClose (handle:lsa);
      }
     }

     SamCloseHandle(handle:handle3);
    }
   }

   SamCloseHandle(handle:handle2);
  }

  SamCloseHandle(handle:handle);
 }

 return ret;
}



#---------------------------------------------------------#
# Function    : NetGroupGetUsers                          #
# Description : Return group members                      #
#---------------------------------------------------------#

function NetGroupGetUsers (group)
{
 local_var ret, handle, domains, sid, handle2, rid, ghandle, members;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x200);
    if (!isnull (handle2))
    {
     rid = SamLookupNamesInDomain (handle:handle2, user:group);
     if (!isnull(rid))
     {
      ghandle = SamOpenGroup (handle:handle2, rid:rid, access:0x10);
      if (!isnull(ghandle))
      {
       members = SamGetMembersInGroup (handle:ghandle);
       if (!isnull(members))
       {
         ret = SamLookupIdsInDomain (handle:handle2, ids:members);
       }
       
       SamCloseHandle(handle:ghandle);
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }
  
  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetInfo                            #
# Description : Return user's info                        #
#---------------------------------------------------------#

function NetUserGetInfo (user)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x200);
    if (!isnull (handle2))
    {
     rid = SamLookupNamesInDomain (handle:handle2, user:user);
     if (!isnull(rid))
     {
      uhandle = SamOpenUser (handle:handle2, rid:rid, access:0x11b);
      if (!isnull(uhandle))
      {
       ret = SamQueryInformationUser (handle:uhandle);
       SamCloseHandle(handle:uhandle);
      }
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }
  
  SamCloseHandle(handle:handle);
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : NetUserGetModals                          #
# Description : Return password policy                    #
# Return      : if level == 1                             #
#                 ret[0] = min pass len                   #
#                 ret[1] = pass history len               #
#                 ret[2] = max pass age                   #
#                 ret[3] = min pass age                   #
#                 ret[4] = force logoff                   #
#               if level == 3                             #
#                 ret[0] = lockout duration               #
#                 ret[1] = lockout observation window     #
#                 ret[2] = lockout treshold               #
# Note        : time in seconds (-1 if infinite)          #
#---------------------------------------------------------#

function NetUserGetModals (level)
{
 local_var ret, handle, domains, sid, handle2, rid, uhandle;

 ret = NULL;

 handle = SamConnect2 ();
 if (!isnull(handle))
 {
  domains = SamEnumerateDomainsInSamServer (handle:handle);
  if (!isnull(domains))
  {
   sid = SamLookupDomainInSamServer (handle:handle, domain:domains[0]);
   if (!isnull(sid))
   {
    handle2 = SamOpenDomain (handle:handle, sid:sid, access:0x205);
    if (!isnull (handle2))
    {
     if (level == 1)
     {
      ret = SamQueryInformationDomain (handle:handle2, level:1);
      if (!isnull (ret))
      {
       tmp = SamQueryInformationDomain (handle:handle2, level:3);
       if (!isnull(tmp))
         ret[max_index(ret)] = tmp[0];
      }
     }
     else if (level == 3)
     {
      ret = SamQueryInformationDomain (handle:handle2, level:12);
     }
    }

    SamCloseHandle(handle:handle2);
   }
  }
  
  SamCloseHandle(handle:handle);
 }

 return ret;
}




#==================================================================#
# Section 7. Registry API                                          #
#==================================================================#



#---------------------------------------------------------#
# Function    : RegConnectRegistry                        #
# Description : Connects to the remote registry.          #
#               if not hkey connects to HKLM              #
# Return      : ret[0] : registry handle                  #
#               ret[1] : registry pipe                    #
#               ret[2] : 1 (Pipe handle)                  #
#---------------------------------------------------------#

function RegConnectRegistry (hkey)
{
 local_var fid, ret, data, type, resp, rep;

 if (isnull (hkey))
   type = HKEY_LOCAL_MACHINE;
 else
   type = hkey;

 fid = bind_pipe (pipe:"\winreg", uuid:"338cd001-2244-31f1-aaaa-900038001003", vers:1);
 if (isnull (fid))
   return NULL;

 data = raw_dword (d:0x00020000) +
        raw_word (w:0x75A0) +
	raw_word (w:0x0000) +
	raw_dword (d:0x02000000) ; # FULL_ACCESS

 data = smb_trans_pipe (fid:fid, data:dce_rpc_request (code:type, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = fid;
 ret[2] = 1;

 return ret;
}



#---------------------------------------------------------#
# Function    : RegOpenKey                                #
# Description : Open the given key                        #
# Return      : ret[0] Key handle                         #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function RegOpenKey (handle, key, mode)
{
 local_var data, resp, rep, name, ret, len;

 name = cstring (string:key);
 len = strlen(name);

 data = handle[0]                     +  # Handle

	class_parameter (ref_id:0x00020000, name:key, size:TRUE) +

	raw_dword (d:0)         +  # Unknown
	raw_dword (d:mode) ;       # Mask
        
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_OPENKEY, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = handle[1];
 ret[2] = 0;
 
 return ret;
}



#---------------------------------------------------------#
# Function    : RegQueryInfoKey                           #
# Description : Retrieve key information                  #
# Return      : returns number of values and sub keys     #
#               ret[0] values                             #
#               ret[1] subkeys                            # 
#---------------------------------------------------------#

function RegQueryInfoKey (handle)
{
 local_var data, resp, rep, ret;

 data = handle[0]          +  # Handle
        raw_word (w:0)     +  # Length
	raw_word (w:0)     +  # Size
	raw_dword (d:0);      # NULL 
 
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_QUERYINFOKEY, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Class (bad parsed here)
 # num subkeys
 # max subkey len
 # reserved
 # num value
 # max value len
 # max valbuf size
 # secdesc len
 # mod time
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 48))
   return NULL;
 
 resp = get_dword (blob:rep, pos:44);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = get_dword (blob:rep, pos:20);
 ret[1] = get_dword (blob:rep, pos:8);

 return ret;
}



#---------------------------------------------------------#
# Function    : RegQueryValue                             #
# Description : Retrieve value about key's item           #
# Return      : returns item value                        #
#               ret[0] type                               #
#               ret[1] value                              #
#---------------------------------------------------------#

function RegQueryValue (handle, item)
{
 local_var data, resp, rep, ret, name, len;
 local_var ref_id, key_type, key_data, code, max_count, offset, actual_count;

 if (strlen(item) > 0)
   name = class_parameter (ref_id:0x00020000, name:item, size:TRUE);
 else
   name = raw_word(w:2) + raw_word (w:0) + raw_dword (d:0);  # (default) value does not work with RegQueryValueEx

 data = handle[0]  +  # Handle

        # Class
        name  +

	# Reserved
        buffer_parameter (ref_id:0x00020004, size:0) +

        # Offered
        buffer_parameter (ref_id:0x00020008, size:0xFFFF) +

        raw_dword (d:0)           +  # unknown
	raw_dword (d:0)           +  # unknown

        # Offered
        buffer_parameter (ref_id:0x0002000C, size:0xFFFF) +
        
	# Returned
        buffer_parameter (ref_id:0x00020010, size:0);


 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_QUERYVALUE, data:data));
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 # Key Type
 ref_id = get_dword (blob:rep, pos:0);
 key_type = get_dword (blob:rep, pos:4);

 # Key Data
 ref_id = get_dword (blob:rep, pos:8);
 max_count = get_dword (blob:rep, pos:12);
 offset = get_dword (blob:rep, pos:16);
 actual_count = get_dword (blob:rep, pos:20);
 if (strlen(rep) < 24+actual_count+20)
   return NULL;

 pos = 0;

 if ((key_type == REG_SZ) || (key_type == REG_EXPAND_SZ) || (key_type == REG_MULTI_SZ))
 {
   key_data = get_string2 (blob:rep, pos:24, len:actual_count, _type:UNICODE_STRING);
   while ((actual_count % 4) != 0)
   {
    actual_count++;
    pos++;
   }
 }
 else if (key_type == REG_DWORD)
 {
  key_data = get_dword (blob:rep, pos:24);
 }
 else
  key_data = substr (rep, 24, 24+actual_count-1);

 # Return code
 code = get_dword (blob:rep, pos:strlen(rep)-4);
 if (code != STATUS_SUCCES)
   return NULL;
 
 ret = NULL;
 ret[0] = key_type;
 ret[1] = key_data;  # we must convert type here
 
 return ret;
}



#---------------------------------------------------------#
# Function    : RegEnumValue                              #
# Description : Retrieve index type and value             #
# Return      : returns key value                         #
#               ret[0] type                               #
#               ret[1] value                              #
#---------------------------------------------------------#

function RegEnumValue (handle, index)
{
 local_var data, resp, rep, ret, name, len;
 local_var unknown1, unknown2, ref_id, key_type, key_name, reserved, val, code;

 data = handle[0]  +  # Handle

	raw_dword (d:index)          +  # num
	raw_dword (d:0x20000000)     +  # unknown

	raw_dword (d:0x20000)        +  # Referent ID
	raw_dword (d:0x1000)         +  # unknown
	raw_dword (d:0)              +  # unknown
	raw_dword (d:0)              +  # unknown

	raw_dword (d:0x20004)        +  # Referent ID
	raw_dword (d:0)              +  # Pointer
	raw_dword (d:0)              +  # reserved

        buffer_parameter (ref_id:0x00020008, size:0) +

        buffer_parameter (ref_id:0x0002000C, size:0);

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_ENUMVALUE, data:data));
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 # Key name
 len = get_word (blob:rep, pos:0);
 unknown1 = get_word (blob:rep, pos:2); # 0x200 ?
 ref_id = get_dword (blob:rep, pos:4);
 unknown2 = get_dword (blob:rep, pos:8);
 reserved = get_dword (blob:rep, pos:12);
 len_2 = get_dword (blob:rep, pos:16);
 
 pos = 20 + len;
 # Extra 2 bytes pad if len_2 odd
 if ((len_2 % 2) == 1)
   pos += 2; 

 if (strlen (rep) < pos+32)
   return NULL;

 key_name = get_string (blob:rep, pos:20);
 
 # Key type
 ref_id = get_dword (blob:rep, pos:pos);
 key_type = get_dword (blob:rep, pos:pos+4);
 reserved = get_dword (blob:rep, pos:pos+8);

 # Offered
 ref_id = get_dword (blob:rep, pos:pos+12);
 val = get_dword (blob:rep, pos:pos+16);

 # Returned
 ref_id = get_dword (blob:rep, pos:pos+20);
 val = get_dword (blob:rep, pos:pos+24);

 # Return code
 code = get_dword (blob:rep, pos:pos+28);
 if (code != STATUS_SUCCES)
   return NULL;
 
 ret = NULL;
 ret[0] = key_type;
 ret[1] = key_name;

 return ret;
}


#---------------------------------------------------------#
# Function    : RegEnumKey                                #
# Description : Returns key's index name                  #
#---------------------------------------------------------#

function RegEnumKey (handle, index)
{
 local_var data, resp, rep, ret, name, len;
 local_var unknown1, unknown2, ref_id, key_type, key_name, reserved;

 data = handle[0]  +  # Handle

	raw_dword (d:index)          +  # num
	raw_dword (d:0x20000000)     +  # unknown

	raw_dword (d:0x20000)        +  # Referent ID
	raw_dword (d:0x1000)         +  # unknown
	raw_dword (d:0)              +  # unknown
	raw_dword (d:0)              +  # unknown

	raw_dword (d:0x20004)        +  # Referent ID
	raw_dword (d:0)              +  # Pointer
	raw_dword (d:0)              +  # reserved
	raw_dword (d:0) ;               # reserved

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_ENUMKEY, data:data));
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 # Key name
 len = get_word (blob:rep, pos:0);
 unknown1 = get_word (blob:rep, pos:2); # 0x200 ?
 ref_id = get_dword (blob:rep, pos:4);
 unknown2 = get_dword (blob:rep, pos:8);
 reserved = get_dword (blob:rep, pos:12);
 len_2 = get_dword (blob:rep, pos:16);
 
 pos = 20 + len;
 # Extra 2 bytes pad if len_2 odd
 if ((len_2 % 2) == 1)
   pos += 2; 

 if (strlen (rep) < pos+20)
   return NULL;

 key_name = get_string (blob:rep, pos:20);
 
 #Returned 
 ref_id = get_dword (blob:rep, pos:pos);
 reserved = get_dword (blob:rep, pos:pos+4);
 reserved = get_dword (blob:rep, pos:pos+8);
 reserved = get_dword (blob:rep, pos:pos+12);

 # Return code
 code = get_dword (blob:rep, pos:pos+16);
 if (code != STATUS_SUCCES)
   return NULL;
 
 ret = key_name;

 return ret;
}



#---------------------------------------------------------#
# Function    : RegCloseKey                               #
# Description : Close key handle                          #
# Return      : 1 on success                              #
#---------------------------------------------------------#

function RegCloseKey (handle)
{
 local_var data, rep, code;

 code = NULL;
 
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_CLOSEKEY, data:handle[0]));
 if (data)
 {
  rep = dce_rpc_parse_response (fid:handle[1], data:data);
  if (rep && (strlen (rep) == 24))
  { 
   # NULL handle (useless) + code
   # Return code
   code = get_dword (blob:rep, pos:20);
  }
 }

 if (handle[2] == 1)
   ret = smb_close (fid:handle[1]);
 
 if (isnull (code) || (code != STATUS_SUCCES) || (ret != 1))
   return NULL;
 
 return 1;
}



#---------------------------------------------------------#
# Function    : RegGetKeySecurity                         #
# Description : Return Key Security Descriptor            #
# Type        : xxx_SECURITY_INFORMATION                  #
#               xxx = DACL, SACL, GROUP, OWNER            #
#               | to use multiple level                   #
#---------------------------------------------------------#

function RegGetKeySecurity (handle, type)
{
 local_var data, rep, ret, len, code, ref_id, offset, size, unknown, sec_desc, size2;
 local_var length, max_count, actual_count;

 data = handle[0] +
        raw_dword (d:type) +
	raw_dword (d:0)    + # Referent ID;
	raw_dword (d:0)    + # Length
	raw_dword (d:0)    + # Offset
	raw_dword (d:0) ;    # Size
	
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_GETKEYSECURITY, data:data));
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 16))
   return NULL;
 
 # Referent ID
 # length
 # offset
 # return code

 ref_id = get_dword (blob:rep, pos:0);
 len = get_dword (blob:rep, pos:4);
 offset = get_dword (blob:rep, pos:8);
 code = get_dword (blob:rep, pos:strlen(rep)-4);
 if (code != ERROR_INSUFFICIENT_BUFFER)
   return NULL;
 
 # Now we do the same request but with the length of our allowed buffer (useless in fact with nasl)

 data = handle[0]                +
        raw_dword (d:type)       +
	raw_dword (d:0x20000)    + # Referent ID;
	raw_dword (d:len)        + # Length
	raw_dword (d:0)          + # Offset
	raw_dword (d:len)        + # Size
	raw_dword (d:0)          + # reserved
	raw_dword (d:0) ;          # reserved
	
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_GETKEYSECURITY, data:data));
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 24))
   return NULL;
 
 # Referent ID
 # length
 # offset
 # return code

 ref_id = get_dword (blob:rep, pos:0);
 len = get_dword (blob:rep, pos:4);
 size = get_dword (blob:rep, pos:8);
 actual_count = get_dword (blob:rep, pos:12);
 offset = get_dword (blob:rep, pos:16);
 max_count = get_dword (blob:rep, pos:20);

 if (strlen (rep) < 24+len+4)
   return NULL;

 sec_desc = substr (rep, 24, 24+len-1);
 sec_desc = parse_security_descriptor (blob:sec_desc);

 code = get_dword (blob:rep, pos:24+len);
 if (code != STATUS_SUCCESS)
   return NULL;
 
 return sec_desc;
}








#==================================================================#
# Section 8. File API                                              #
#==================================================================#



function get_win32_find_data_filename (struct)
{
 local_var len;

 if (strlen(struct) < 94)
   return NULL;

 len = get_dword (blob:struct, pos:60);
 if (strlen(struct) < 94 + len)
   return NULL;

 return get_string2 (blob:struct, pos:94, len:len);
}


function get_win32_find_data_fileattributes (struct)
{
 local_var len;

 if (strlen(struct) < 94)
   return NULL;

 return get_dword (blob:struct, pos:56);
}


#---------------------------------------------------------#
# Function    : FindFirstFile                             #
# Description : Return First file in WIN32_FIND_DATA      #
# Return      : ret[0] = file handle                      #
#               ret[1] = file name                        #
#               ret[2] = file attributes                  #
#               full handle = ret (to use with NextFile)  #
#---------------------------------------------------------#

function FindFirstFile (pattern)
{
 local_var ret, parameters, search_id, search_count, end_of_search, ea_error_offset, last_name_offset;
 local_var pad, data, index, pos, file_struct;

 parameters = raw_word (w:0x16)   + # Default search : include HIDDEN/SYSTEM/DIRECTORY 
              raw_word (w:0xFFFF) + # Max buffer search count
              raw_word (w:6)      + # Close if EOS is reached / RESUME
              raw_word (w:260)    + # Default level of interest
              raw_dword (d:0)     + # Storage type
              cstring (string:pattern);

 ret = smb_trans2 (param:parameters, data:NULL, max_pcount:18, command:1); 
 if (!ret || (strlen (ret) < 14))
   return NULL;

 # FIND_FIRST2 Parameters
 search_id = get_word (blob:ret, pos:0);
 search_count = get_word (blob:ret, pos:2);
 end_of_search = get_word (blob:ret, pos:4);
 ea_error_offset = get_word (blob:ret, pos:6);
 last_name_offset = get_word (blob:ret, pos:8);

 # Padding
 pad = get_word (blob:ret, pos:10);

 # FIND_FIRST2 Data
 data = substr (ret, 12, strlen(ret)-1);

 # If no data we quit
 if (search_count <= 0)
   return NULL;
 
 index = 1;
 pos = 0;
 
 # FIND_FIRST2 Data
 size = get_word (blob:data, pos:pos);
 if (strlen (data) < size)
   return NULL;
 
 file_struct = substr (data, pos, pos+size-1);

 pos += size;
 index++;

 ret = NULL;
 ret[0] = raw_word (w:search_id) +
          raw_word (w:search_count) +
          raw_word (w:end_of_search) +
          raw_word (w:index) +
          raw_dword (d:pos) +
          data;

 ret[1] = get_win32_find_data_filename (struct:file_struct);
 ret[2] = get_win32_find_data_fileattributes (struct:file_struct);

 return ret;
}



#---------------------------------------------------------#
# Function    : FindNextFile                              #
# Description : Return Next file in WIN32_FIND_DATA       #
# Return      : ret[0] = file handle                      #
#               ret[1] = file name                        #
#               full handle = ret                         #
#---------------------------------------------------------#

function FindNextFile (handle)
{
 local_var ret, parameters, search_id, search_count, end_of_search, ea_error_offset, last_name_offset;
 local_var pad, data, index, pos, file_struct;

 if (strlen (handle[0]) < 13)
   return NULL;

 search_id = get_word (blob:handle[0], pos:0);
 search_count = get_word (blob:handle[0], pos:2);
 end_of_search = get_word (blob:handle[0], pos:4);
 index = get_word (blob:handle[0], pos:6);
 pos = get_dword (blob:handle[0], pos:8);
 data = substr (handle[0], 12, strlen (handle[0]) - 1);

 if (index > search_count)
 {
  if (end_of_search == 1)
    return NULL;

  parameters = raw_word (w:search_id) + # Search ID
               raw_word (w:0xFFFF)    + # Max search buffer size
               raw_word (w:260)       + # Default level of interest
               raw_dword (d:0)        + # storage type
               raw_word (w:6)         + # Close if EOS is reached / RESUME
               cstring (string:handle[1]);

  ret = smb_trans2 (param:parameters, data:NULL, max_pcount:8, command:2);
  if (!ret || (strlen (ret) < 10))
    return NULL;

  # FIND_FIRST2 Parameters
  search_count = get_word (blob:ret, pos:0);
  end_of_search = get_word (blob:ret, pos:2);
  ea_error_offset = get_word (blob:ret, pos:4);
  last_name_offset = get_word (blob:ret, pos:6);

  # FIND_FIRST2 Data
  data = substr (ret, 8, strlen(ret)-1);

  # If no data we quit
  if (search_count <= 0)
    return NULL;
 
  index = 1;
  pos = 0;
 } 
 
 size = get_word (blob:data, pos:pos);
 if (strlen (data) < size)
   return NULL;

 #last elem next offset param is null
 if (size == 0)
   size = strlen (data);
 
 file_struct = substr (data, pos, pos+size-1);
 pos += size;
 index++;

 ret = NULL;
 ret[0] = raw_word (w:search_id) +
          raw_word (w:search_count) +
          raw_word (w:end_of_search) +
          raw_word (w:index) +
          raw_dword (d:pos) +
          data;


 ret[1] = get_win32_find_data_filename (struct:file_struct);
 ret[2] = get_win32_find_data_fileattributes (struct:file_struct);

 return ret;
}



#---------------------------------------------------------#
# Function    : CreateFile                                #
# Description : open a file                               #
#               return file handle                        #
#---------------------------------------------------------#

function CreateFile (file, desired_access, file_attributes, share_mode, create_disposition)
{
 return smb_create_and_x (name:file,
                          desired_access:desired_access,
                          flags_attributes:file_attributes,
                          share_mode:share_mode,
                          create_disposition:create_disposition,
                          create_options:0);
}



#---------------------------------------------------------#
# Function    : ReadFile                                  #
# Description : Read data from file                       #
#---------------------------------------------------------#

function ReadFile (handle, offset, length)
{
 local_var fid;

 fid = handle[0];

 return smb_read_and_x (fid:fid, offset:offset, length:length);
}



#---------------------------------------------------------#
# Function    : WriteFile                                 #
# Description : write data into file                      #
#---------------------------------------------------------#

function WriteFile (handle, offset, mode, data)
{
 local_var fid;

 fid = handle[0];

 return smb_write_and_x (fid:fid, offset:offset, mode:mode, data:data);
}



#---------------------------------------------------------#
# Function    : CloseFile                                 #
# Description : close a file                              #
#---------------------------------------------------------#

function CloseFile (handle)
{
 local_var fid;

 fid = handle[0];

 return smb_close (fid:fid);
}




#---------------------------------------------------------#
# Function    : GetSecurityInfo                           #
# Description : return security information               #
# Note        : only works with a file                    #
#---------------------------------------------------------#

function GetSecurityInfo (handle, level)
{
 local_var parameters, ret, len;

 parameters = raw_word (w:handle[0]) + # FID
              raw_word (w:0)         + # reserved
              raw_dword (d:level);

 ret = smb_nt_trans (param:parameters, data:NULL, command:0x06, max_pcount:4, max_dcount:0);
 if (strlen(ret) != 4)
   return NULL;

 len = get_dword (blob:ret, pos:0);
 ret = smb_nt_trans (param:parameters, data:NULL, command:0x06, max_pcount:4, max_dcount:len);
 if (strlen(ret) < 4)
   return NULL;

 len = get_dword (blob:ret, pos:0);
 if (strlen(ret) != 4 + len)
   return NULL;

 return parse_security_descriptor (blob:substr(ret, 4, strlen(ret)-1));
}


#---------------------------------------------------------#
# Function    : GetFileSize                               #
# Description : return file size                          #
#---------------------------------------------------------#

function GetFileSize (handle)
{
 local_var size;

 size = handle[1];

 # size = low DWORD + high DWORD
 # we just don't care about high DWORD for the moment
 return get_dword (blob:size, pos:0);
}



function check_version (size, offset)
{
 local_var i, tmp, idx, value_len, value, sig, pos, ret;

 # we read rsrc section by block of 1000 bytes
 for (i=0; i<size; i+=970)
 {
  tmp = ReadFile (handle:handle, offset:offset+i, length:1000);
  if (!tmp)
    return NULL;

  pattern = unicode (string:"VS_VERSION_INFO");
  idx = stridx (tmp, pattern);
  if (idx != -1)
  {
   # we found it
   value_len = get_word (blob:tmp, pos:idx-4);
   if ((value_len + (value_len%4) + strlen(pattern) + idx) > strlen (tmp))
   {
     tmp = ReadFile (handle:handle, offset:offset+i+idx-4, length:1000);
     if (!tmp)
       return NULL;
     idx = 4;
   }
   pos = idx + 34 + (value_len%4);
   if (value_len < 16)
     return NULL;

   value = substr (tmp, pos, pos+value_len-1);
   if (strlen(value) != value_len)
     return NULL;

   sig = substr(value,0,3);
   if ("bd04effe" >!< hexstr(sig))
     return NULL;

   ret = NULL;
   ret[0] = get_word (blob:value, pos:10);
   ret[1] = get_word (blob:value, pos:8);
   ret[2] = get_word (blob:value, pos:14);
   ret[3] = get_word (blob:value, pos:12);
   return ret; 
  }
 }

 return NULL;
}




#---------------------------------------------------------#
# Function    : GetFileVersion                            #
# Description : return file version (exe,dll,...)         #
# Return      : ret[0] = version 0                        #
#               ret[1] = version 1                        #
#               ret[2] = version 2                        #
#               ret[3] = version 3                        #
#---------------------------------------------------------#

function GetFileVersion (handle)
{
 local_var dos_header, sig, e_lfanew, nt_header, number_of_sections, size_optional_header, i;
 local_var offset, size, sections, pos, idx, tmp, pattern, rsrc, r_pattern, ret;


 # Some exe packers remove FileInfo structure from ressource section
 # So we do like Windows We read first 32768 octets and with chances (like opera/aspack)

 ret = check_version (size:32768, offset:0);
 if (!isnull(ret))
   return ret; 

 # We first parse IMAGE_DOS_HEADER
 dos_header = ReadFile (handle:handle, offset:0, length:64);
 if (!dos_header || (strlen(dos_header) != 64))
   return NULL;

 sig = substr(dos_header, 0, 1);
 if ("MZ" >!< sig)
   return NULL;

 e_lfanew = get_dword (blob:dos_header, pos:60);


 # We now parse Signature + IMAGE_FILE_HEADER
 nt_header = ReadFile (handle:handle, offset:e_lfanew, length:24);
 if (!nt_header || (strlen(nt_header) != 24))
   return NULL;

 sig = substr(nt_header, 0, 1);
 if ("PE" >!< sig)
   return NULL;

 number_of_sections = get_word (blob:nt_header, pos:6);
 size_optional_header = get_word (blob:nt_header, pos:20);

 
 # We now parse sections
 offset = e_lfanew + 24 + size_optional_header;
 size = number_of_sections * 40;
 sections = ReadFile (handle:handle, offset:offset, length:size);
 if (!sections || (strlen(sections) != size))
   return NULL;

 pos = rsrc = 0;
 r_pattern = ".rsrc" + raw_string (0,0,0);

 for (i=0; i<number_of_sections; i++)
 {
  name = substr(sections, pos, pos+7);
  size = get_dword (blob:sections, pos:pos+16);
  offset = get_dword (blob:sections, pos:pos+20);

  if (r_pattern >< name)
  {
   rsrc = 1;
   break;
  }

  pos += 40;
 }

 # if no rsrc section left
 if (rsrc == 0)
   return NULL; 

 return check_version (size:size, offset:offset); 
}





#==================================================================#
# Section 9. LSA API                                               #
#==================================================================#



#---------------------------------------------------------#
# Function    : LsaOpenPolicy                             #
# Description : Open LSA Policy                           #
# Note        : access mode is optionnal                  #
#---------------------------------------------------------#

function LsaOpenPolicy (desired_access)
{
 local_var fid, ret, data, type, resp, rep, daccess;

 if (!isnull (desired_access))
   daccess = desired_access;
 else
   daccess = 0x000f0fff; 

 fid = bind_pipe (pipe:"\lsarpc", uuid:"12345778-1234-abcd-ef00-0123456789ab", vers:0);
 if (isnull (fid))
   return NULL;

 data = class_parameter (ref_id:0x00020000, name:"\\" + session_get_hostname ()) +

        # LSA_OBJECT_ATTRIBUTES (NULL)
        raw_dword (d:0)          + # length
        raw_dword (d:0)          + # RootDirectory (HANDLE)
        raw_dword (d:0)          + # ObjectName (NULL)
        raw_dword (d:0)          + # Attributes
        raw_dword (d:0)          + # SecurityDescriptor (NULL Pointer)
        raw_dword (d:0)          + # SecurityQualityOfService (NULL Pointer)       

        # Desired Access
        raw_dword (d:daccess) ;
 data = smb_trans_pipe (fid:fid, data:dce_rpc_request (code:OPNUM_LSAOPENPOLICY, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = fid;
 ret[2] = 1;

 return ret;
}


#---------------------------------------------------------#
# Function    : LsaQueryInformationPolicy                 #
# Description : Query Policy Information                  #
#                                                         #
# Supports    : PolicyAccountDomainInformation            #
#               PolicyPrimaryDomainInformation            #
#                                                         #
# return      : ret[0] hostname/domain                    #
#               ret[1] raw sid                            #          
#---------------------------------------------------------#

function LsaQueryInformationPolicy (handle, level)
{
 local_var data, resp, rep, name, ret, len, ref_id, pad, length, size;
 local_var max_count, offset, actual_count, hostname, pos, count, sid, sid_ref_id, auditing;

 data = handle[0]                     +  # Handle
        raw_word (w:level) ;             # Info level
        
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_LSAQUERYINFO, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 10))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;


 ref_id = get_dword (blob:rep, pos:0);
 level = get_word (blob:rep, pos:4);


 if ((level == PolicyAccountDomainInformation) || (level == PolicyPrimaryDomainInformation))
 {

  if (strlen(rep) < 36)
    return NULL;

  # POLICY_ACCOUNT_DOMAIN_INFO
  pad = get_word (blob:rep, pos:6);

  # size is the total size of the remote buffer, length is data length in the buffer
  length = get_word (blob:rep, pos:8);
  size = get_word (blob:rep, pos:10);

  # ref_id = get_dword (blob:rep, pos:12); # string refid
  sid_ref_id = get_dword (blob:rep, pos:16); # sid refid

  # LSA_UNICODE_STRING
  max_count = get_dword (blob:rep, pos:20);
  offset = get_dword (blob:rep, pos:24);
  actual_count = get_dword (blob:rep, pos:28);

  if (strlen(rep) < 36 + length)
    return NULL;

  hostname = get_string2 (blob:rep, pos:32, len:length, _type:UNICODE_STRING);
    
  while ((length % 4) != 0)
    length ++;

  pos = 32 + length;

  if (sid_ref_id != 0)
  {
   # Domain SID
   count = get_dword (blob:rep, pos:pos);
   sid = substr (rep, pos+4, strlen(rep) - 5);
  }
  else
    sid = NULL;

  ret = NULL;
  ret[0] = hostname;
  ret[1] = sid;

  return ret;
 }

 if (level == PolicyAuditEventsInformation)
 {
  if (strlen(rep) != 64)
    return NULL;

  auditing = get_dword (blob:rep, pos:8);
  if (auditing == 0)
    return NULL;

  ref_id = get_dword (blob:rep, pos:12);
  actual_count = get_dword (blob:rep, pos:16);
  max_count = get_dword (blob:rep, pos:20);

  if (actual_count != 9)
    return NULL;

  ret = NULL;
  for (i=0; i<9; i++)
     ret[i] = get_dword (blob:rep, pos:24+i*4);  

  return ret;
 } 
}



#---------------------------------------------------------#
# Function    : LsaLookupSid                              #
# Description : Translate PSID to UserNames               #
#               array of sid (InformationPolicy sid)      #
#                                                         #
# Return      : array of sid_type + name                  #
#               sid_type = raw_dword                      #
#---------------------------------------------------------#

function LsaLookupSid (handle, sid_array)
{
 local_var data, resp, rep, name, ret, len, ref_id, level, pad, length, size;
 local_var max_count, offset, actual_count, hostname, pos, count, sid, sid_ref_id;
 local_var names, ref_idm, name_length, name_size, name_ref_id, sid_type, index, unknown;
 local_var sid_count, i;

 ref_id = 0x00020000;

 data = handle[0]                     +  # Handle

        # PSID Array
        raw_dword (d:max_index (sid_array))  + # number of sid in PSID Array
        raw_dword (d:ref_id)                 + # Referent ID
        raw_dword (d:max_index (sid_array)) ;  # max_count

 ref_id++;

 # ref_id
 foreach sid (sid_array)
 {
  data += raw_dword (d:ref_id);

  ref_id++;
 }

 foreach sid (sid_array)
 {
  count = ord(sid[1]);
  
  data += raw_dword (d:count)   +
          sid ;
 }

 data += raw_dword (d:0)        + # count = 0
         raw_dword (d:0)        + # NULL pointer (LSA_TRANSLATED_NAMES)

         raw_dword (d:1)        + # Level (nothing else seems to work)
         raw_dword (d:0)        ; # Num mapped ?
 #        raw_dword (d:0)        + # Unknown
 #        raw_dword (d:2) ;        # Unknown
        
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_LSALOOKUPSID, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if ((resp != STATUS_SUCCESS) && (resp != STATUS_SOME_NONE_MAPPED))
   return NULL;

 # LSA REF DOMAIN LIST Pointer
 ref_id = get_dword (blob:rep, pos:0);
 count = get_dword (blob:rep, pos:4);

 # Trust information array
 ref_id = get_dword (blob:rep, pos:8);
 max_count = get_dword (blob:rep, pos:12);
 count = get_dword (blob:rep, pos:16);

 pos = 20;

 # for each domain info
 pos = pos + count*12;

 for (i=0; i<count; i++)
 {
  if (strlen(rep) < pos + 12)
    return NULL;

  # name array
  max_count = get_dword (blob:rep, pos:pos+0);
  offset = get_dword (blob:rep, pos:pos+4);
  actual_count = get_dword (blob:rep, pos:pos+8);

  if (strlen(rep) < pos + 12 + actual_count*2)
    return NULL;

  name = substr (rep, pos+12, pos+12+actual_count*2-1);

  pos = pos+12+actual_count*2;

  if ((actual_count*2)%4)
    pos += 2;

  # SID
  sid_count = get_dword (blob:rep, pos:pos);
  if (strlen(rep) < pos + 4+8+sid_count*4)
   return NULL;

  sid = substr (rep, pos+4, pos+4+8+sid_count*4-1);
  pos = pos+4+8+sid_count*4;
 }

 # LSA_TRANSLATED_NAME_EX pointer
 count = get_dword (blob:rep, pos:pos);
 ref_id = get_dword (blob:rep, pos:pos+4);
 max_count = get_dword (blob:rep, pos:pos+8);

 pos = pos + 12;

 names = NULL;

 # for each names
 for (i=0; i<count; i++)
 {
  if (strlen(rep) < pos + 20)
   return NULL;

  sid_type = get_word (blob:rep, pos:pos);
  names[i] = raw_dword (d:sid_type);
  length = get_word (blob:rep, pos:pos+4);
  size = get_word (blob:rep, pos:pos+6);
  ref_id = get_dword (blob:rep, pos:pos+8);
  index = get_dword (blob:rep, pos:pos+12);

  pos = pos+16;
 }

 # we get names now
 for (i=0; i<count; i++)
 {
  if (strlen(rep) < pos + 12)
   return NULL;

  max_count = get_dword (blob:rep, pos:pos);
  offset = get_dword (blob:rep, pos:pos+4);
  actual_count = get_dword (blob:rep, pos:pos+8);

  if (strlen(rep) < pos + 12 + actual_count*2)
   return NULL;

  names[i] += get_string2 (blob:rep, pos:pos+12, len:actual_count*2, _type:UNICODE_STRING);
  if ((actual_count*2)%4)
    pos +=2;

  pos = pos+12+actual_count*2;
 }

 return names;
}



#---------------------------------------------------------#
# Function    : LsaLookupNames                            #
# Description : Translate UserNames to SID                #
#               array of usernames                        #
#                                                         #
# Return      : array of sid_type + rid                   #
#               sid_type = rid = raw_dword                #
#---------------------------------------------------------#

function LsaLookupNames (handle, name_array)
{
 local_var data, resp, rep, name, ret, len, ref_id, level, pad, length, size;
 local_var max_count, offset, actual_count, hostname, pos, count, sid, sid_ref_id;
 local_var names, ref_idm, name_length, name_size, name_ref_id, sid_type, index, unknown;
 local_var sid_count, uname;

 ref_id = 0x00020000;

 data = handle[0]                     +  # Handle

        # Account array
        raw_dword (d:max_index (name_array))  + # number of sid in PSID Array
        raw_dword (d:max_index (name_array)) ;  # max_count

 ref_id++;

 # ref_id
 foreach name (name_array)
 {
  if (session_is_unicode() == 0)
  {
   session_set_unicode (unicode:1);
   uname = cstring (string:name,_null:1);
   session_set_unicode (unicode:0);
  }
  else
  {
   uname = cstring (string:name, _null:1);
  } 

  data += raw_word (w:strlen(uname)) +
          raw_word (w:strlen(uname)) +
          raw_dword (d:ref_id);

  ref_id++;
 }

 foreach name (name_array)
 {
  if (session_is_unicode() == 0)
  {
   session_set_unicode (unicode:1);
   uname = cstring (string:name,_null:1);
   session_set_unicode (unicode:0);
  }
  else
  {
   uname = cstring (string:name,_null:1);
  } 
  
  data += raw_dword (d:strlen(uname)/2)   +
          raw_dword (d:0)                 + # offset
          raw_dword (d:strlen(uname)/2)   +
          uname + raw_word (w:0);
 }

 data += raw_dword (d:0)        + # count = 0
         raw_dword (d:0)        + # NULL pointer (LSA_TRANSLATED_NAMES)

         raw_dword (d:1)        + # Level (nothing else seems to work)
         raw_dword (d:0)        ; # Num mapped ?
        
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_LSALOOKUPNAMES, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 20))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if ((resp != STATUS_SUCCESS) && (resp != STATUS_SOME_NONE_MAPPED))
   return NULL;

 # LSA REF DOMAIN LIST Pointer
 ref_id = get_dword (blob:rep, pos:0);
 count = get_dword (blob:rep, pos:4);

 # Trust information array
 ref_id = get_dword (blob:rep, pos:8);
 max_count = get_dword (blob:rep, pos:12);
 count = get_dword (blob:rep, pos:16);

 pos = 20;

 # for each domain info
 
 for (i=0; i < count; i++)
 {
  if (strlen(rep) < pos + 24)
    return NULL;

  name_length = get_word (blob:rep, pos:pos);
  name_size = get_word (blob:rep, pos:pos+2);  # max size of name buffer (we are happy to know that)
  name_ref_id = get_dword (blob:rep, pos:pos+4);
  sid_ref_id = get_dword (blob:rep, pos:pos+8);

  # name array
  max_count = get_dword (blob:rep, pos:pos+12);
  offset = get_dword (blob:rep, pos:pos+16);
  actual_count = get_dword (blob:rep, pos:pos+20);

  if (strlen(rep) < pos + 28 + name_length)
    return NULL;

  name = substr (rep, pos+24, pos+24+name_length-1);
  pos = pos+24+name_length;

  # SID
  sid_count = get_dword (blob:rep, pos:pos);

  if (strlen(rep) < pos + 4+8+count*4)
   return NULL;

  sid = substr (rep, pos+4, pos+4+8+count*4-1);

  pos = pos+4+8+sid_count*4;
 }

 # LSA_TRANSLATED_SID
 count = get_dword (blob:rep, pos:pos);
 ref_id = get_dword (blob:rep, pos:pos+4);
 max_count = get_dword (blob:rep, pos:pos+8);

 pos = pos + 12;
 sid = NULL;

 # for each names
 for (i=0; i<count; i++)
 {
  if (strlen(rep) < pos + 12)
   return NULL;

  sid_type = get_dword (blob:rep, pos:pos);
  rid = get_dword (blob:rep, pos:pos+4);
  index = get_dword (blob:rep, pos:pos+8);

  sid[i] = raw_dword (d:sid_type) + raw_dword (d:rid);

  pos = pos+12;
 }

 return sid;
}


#---------------------------------------------------------#
# Function    : LsaClose                                  #
# Description : Close lsa handle                          #
# Return      : 1 on success                              #
#---------------------------------------------------------#

function LsaClose (handle)
{
 local_var data, rep, code, ret;

 code = NULL;
 
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_LSACLOSE, data:handle[0]));
 if (data)
 {
  rep = dce_rpc_parse_response (fid:handle[1], data:data);
  if (rep && (strlen (rep) == 24))
  { 
   # NULL handle (useless) + code
   # Return code
   code = get_dword (blob:rep, pos:20);
  }
 }

 if (handle[2] == 1)
   ret = smb_close (fid:handle[1]);
 
 if (isnull (code) || (code != STATUS_SUCCES) || (ret != 1))
   return NULL;
 
 return 1;
}




#==================================================================#
# Section 9. Service API                                           #
#==================================================================#


function class_name (name)
{
 local_var tmp, len, ret;

 if (isnull(name))
   return raw_dword (d:0);

 tmp = cstring (string:name);
 len  = strlen (tmp);

 while ((strlen(tmp)%4) != 0)
   tmp += raw_byte (b:0);

 if (session_is_unicode() == 1)
   len = len / 2;

 ret =  raw_dword (d:len)             + # length
        raw_dword (d:0)               + # offset
        raw_dword (d:len)             + # size
        tmp;                            # hostname

 return ret;
}


#---------------------------------------------------------#
# Function    : OpenSCManager                             #
# Description : Open Service Manager                      #
#---------------------------------------------------------#

function OpenSCManager (access_mode)
{
 local_var fid, ret, data, type, resp, rep, name, opnum;

 fid = bind_pipe (pipe:"\svcctl", uuid:"367abb81-9844-35f1-ad32-98f038001003", vers:2);
 if (isnull (fid))
   return NULL;

 if (session_is_unicode() == 1)
   opnum = OPNUM_OPENSCMANAGERW;
 else
   opnum = OPNUM_OPENSCMANAGERA;
 
 data = raw_dword (d:0x0020000)                       + # ref_id
        class_name (name:"\\"+session_get_hostname()) +
        raw_dword (d:0)                               + # NULL database pointer 
        raw_dword (d:access_mode) ;                     # Desired Access

 data = smb_trans_pipe (fid:fid, data:dce_rpc_request (code:opnum, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = fid;
 ret[2] = 1;

 return ret;
}



#---------------------------------------------------------#
# Function    : OpenService                               #
# Description : Open the given service                    #
# Return      : ret[0] service handle                     #
#               ret[1] FID                                #
#               ret[2] reserved                           #
#---------------------------------------------------------#

function OpenService (handle, service, access_mode)
{
 local_var data, resp, rep, tmp, ret, len;

 if (session_is_unicode() == 1)
   opnum = OPNUM_OPENSERVICEW;
 else
   opnum = OPNUM_OPENSERVICEA;

 data = handle[0]                     +  # Handle
        class_name(name:service)      +  # service name  
        raw_dword (d:access_mode) ;
        
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:opnum, data:data));
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;
 
 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = handle[1];
 ret[2] = 0;
 
 return ret;
}


#---------------------------------------------------------#
# Function    : GetService                                #
# Description : Return service information                #
# Return      :                                           #
#                                                         #
#  BYTE  Name[];                                          #
#  BYTE  Description[];                                   #
#  DWORD dwServiceType;                                   #
#  DWORD dwCurrentState;                                  #
#  DWORD dwControlsAccepted;                              #
#  DWORD dwWin32ExitCode;                                 #
#  DWORD dwServiceSpecificExitCode;                       #
#  DWORD dwCheckPoint;                                    #
#  DWORD dwWaitHint;                                      #
#---------------------------------------------------------#

function GetService (service)
{
 local_var tab, ret, pos, name, desc;

 tab = split (service, sep:raw_byte(b:0x01));
 ret = NULL;

 pos = 0;
 name = desc = NULL;
 
 while (ord(service[pos]) != 0x01)
 {
  name += service[pos];
  pos++;
 }

 pos++;

 while (ord(service[pos]) != 0x01)
 {
  desc += service[pos];
  pos++;
 }

 pos++;

 ret[0] = name;
 ret[1] = desc;
 ret[2] = get_dword (blob:tab[2], pos:pos);
 ret[3] = get_dword (blob:tab[2], pos:pos+4);
 ret[4] = get_dword (blob:tab[2], pos:pos+8);
 ret[5] = get_dword (blob:tab[2], pos:pos+12);
 ret[6] = get_dword (blob:tab[2], pos:pos+16);
 ret[7] = get_dword (blob:tab[2], pos:pos+20);
 ret[8] = get_dword (blob:tab[2], pos:pos+24);
 
 return ret;
}


#---------------------------------------------------------#
# Function    : EnumServicesStatus                        #
# Description : Enumerate services                        #
# Return      : array of ENUM_SERVICE_STATUS              #
#               Use GetService to parse each elem         #
#---------------------------------------------------------#

function EnumServicesStatus (handle, type, state)
{
 local_var data, resp, rep, ret, length, pos, name_pt, desc_pt, service_status, opnum, i;

 if (session_is_unicode() == 1)
   opnum = OPNUM_ENUMSERVICEW;
 else
   opnum = OPNUM_ENUMSERVICEA;

 # We must first send a 0 byte array else if we use a 0xFFFF length array
 # Windows will return 0xFFFF bytes instead of the real buffer size ...

 data = handle[0]                     +  # Handle
        raw_dword (d:type)            +  # service type
        raw_dword (d:state)           +  # service state
        raw_dword (d:0)               +  # buffer size
        raw_dword (d:0x00020000)      +  # pointer
        raw_dword (d:0) ;                # NULL pointer

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:opnum, data:data));
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 10))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != ERROR_MORE_DATA)
   return NULL;

 length = get_dword (blob:rep, pos:4);

 data = handle[0]                     +  # Handle
        raw_dword (d:type)            +  # service type
        raw_dword (d:state)           +  # service state
        raw_dword (d:length)          +  # buffer size
        raw_dword (d:0x00020000)      +  # pointer
        raw_dword (d:0) ;                # NULL pointer

 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:opnum, data:data));
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 4))
   return NULL;

 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 length = get_dword (blob:rep, pos:0);
 pos = 4 + length + length%4; 

 if (strlen (rep) != pos+20)
   return NULL;

 array = substr (rep, 4, length+4-1);

 # unknown1 = get_dword (blob:rep, pos:pos);

 num = get_dword (blob:rep, pos:pos+4);

 # ref_id = get_dword (blob:rep, pos:pos+8);
 # pointer = get_dword (blob:rep, pos:pos+12);

 pos = 0;
 ret = NULL;

 # for each service
 for (i=0; i<num; i++)
 {
  name_pt = get_dword (blob:array, pos:pos);
  desc_pt = get_dword (blob:array, pos:pos+4);

  # SERVICE_STATUS structure : length = 28
  service_status = substr (array, 8, 35);

  pos += 36;

  ret[i] = get_string (blob:array, pos:name_pt) + raw_byte(b:0x01) +
           get_string (blob:array, pos:desc_pt) + raw_byte(b:0x01) + 
           service_status;
 }

 return ret;
}


#---------------------------------------------------------#
# Function    : ControlService                            #
# Description : Send control message to service           #
#---------------------------------------------------------#

function ControlService (handle, control)
{
 local_var data, resp, rep, ret;

 data = handle[0]                     +  # Handle
        raw_dword (d:control) ;          # Info level
        
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SERVICECONTROL, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 10))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = get_dword (blob:rep, pos:0);    # service type
 ret[1] = get_dword (blob:rep, pos:4);    # current state 
 ret[2] = get_dword (blob:rep, pos:8);    # controls accepted
 ret[3] = get_dword (blob:rep, pos:12);   # exit code
 ret[4] = get_dword (blob:rep, pos:16);   # service specific exit code
 ret[5] = get_dword (blob:rep, pos:20);   # check point
 ret[6] = get_dword (blob:rep, pos:24);   # wait hint

 return ret;
}


#---------------------------------------------------------#
# Function    : CreateService                             #
# Description : Add a new service                         #
#---------------------------------------------------------#

function CreateService (handle, service_name, display_name, desired_access, service_type, start_service, error_control, path, load_order_group, service_start_name, password)
{
 local_var data, resp, rep, ret, unknown, opnum, name;

 if (session_is_unicode() == 1)
   opnum = OPNUM_CREATESERVICEW;
 else
   opnum = OPNUM_CREATESERVICEA;

 data = handle[0]                            +  # Handle
        class_name (name:service_name)       +  # Service Name
        raw_dword (d:0x00020000)             +  # Ref ID
        class_name (name:display_name)       +  # Display Name
        raw_dword (d:desired_access)         +  # Desired Access
        raw_dword (d:service_type)           +  # Service Type
        raw_dword (d:start_service)          +  # StartService
        raw_dword (d:error_control)          +  # ErrorControl
        class_name (name:path)               +  # Path
        class_name (name:load_order_group)   +  # LoadOrderGroup
        raw_dword (d:0)                      +  # pointer to tagid
        raw_dword (d:0)                      +  # array of string
        class_name (name:service_start_name) +  # Service Start Name
        class_name (name:password)           +  # Password (depend of Service Start Name)
        raw_dword (d:0)                      +  # unknown
        raw_dword (d:0) ;                       # unknown
       
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:opnum, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 28))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 unknown = get_dword (blob:rep, pos:0);

 ret = NULL;
 ret[0] = substr (rep, 4, 23);
 ret[1] = handle[1];
 ret[2] = 0;
 
 return ret;
}


#---------------------------------------------------------#
# Function    : StartService                              #
# Description : Start a service                           #
#---------------------------------------------------------#

function StartService (handle)
{
 local_var data, resp, rep, ret, unknown, opnum, name;

 if (session_is_unicode() == 1)
   opnum = OPNUM_STARTSERVICEW;
 else
   opnum = OPNUM_STARTSERVICEA;

 data = handle[0] + #handle
        raw_dword (d:0) + # NULL pointer
        raw_dword (d:0) ; # NULL pointer
       
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:opnum, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 4))
   return NULL;
 
 resp = get_dword (blob:rep, pos:0);
 if (resp != STATUS_SUCCESS)
   return NULL;

 return 1;
}


#---------------------------------------------------------#
# Function    : DeleteService                             #
# Description : Delete a service                          #
#---------------------------------------------------------#

function DeleteService (handle)
{
 local_var data, resp, rep, ret;

 data = handle[0] ; # Handle
       
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_DELETESERVICE, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 4))
   return NULL;
 
 resp = get_dword (blob:rep, pos:0);
 if (resp != STATUS_SUCCESS)
   return NULL;
 
 return ret;
}



#---------------------------------------------------------#
# Function    : CloseServiceHandle                        #
# Description : Close service handle                      #
# Return      : 1 on success                              #
#---------------------------------------------------------#

function CloseServiceHandle (handle)
{
 local_var data, rep, code;

 code = NULL;
 
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_SERVICECLOSE, data:handle[0]));
 if (data)
 {
  rep = dce_rpc_parse_response (fid:handle[1], data:data);
  if (rep && (strlen (rep) == 24))
  { 
   # NULL handle (useless) + code
   # Return code
   code = get_dword (blob:rep, pos:20);
  }
 }

 if (handle[2] == 1)
   ret = smb_close (fid:handle[1]);
 
 if (isnull (code) || (code != STATUS_SUCCES) || (ret != 1))
   return NULL;
 
 return 1;
}


#---------------------------------------------------------#
# Function    : QueryServiceStatus                        #
# Description : Query service status                      #
#---------------------------------------------------------#

function QueryServiceStatus (handle)
{
 local_var data, resp, rep, ret;

 data = handle[0] ;  # Handle
        
 data = smb_trans_pipe (fid:handle[1], data:dce_rpc_request (code:OPNUM_QUERYSERVICE, data:data));
 if (!data)
   return NULL;
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) < 10))
   return NULL;
 
 resp = get_dword (blob:rep, pos:strlen(rep)-4);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = get_dword (blob:rep, pos:0);    # service type
 ret[1] = get_dword (blob:rep, pos:4);    # current state 
 ret[2] = get_dword (blob:rep, pos:8);    # controls accepted
 ret[3] = get_dword (blob:rep, pos:12);   # exit code
 ret[4] = get_dword (blob:rep, pos:16);   # service specific exit code
 ret[5] = get_dword (blob:rep, pos:20);   # check point
 ret[6] = get_dword (blob:rep, pos:24);   # wait hint

 return ret;
}






#==================================================================#
# Section 10. Old API wrapper                                      #
#==================================================================#


# This function MUST be redone                #
# we must check for local user (admin rights) #
#                   domain user (admin group) #

function registry_key_writeable_by_non_admin(security_descriptor)
{
 local_var pdacl, dacl, item, access_rights, sid;
 local_var ADMIN_SID, LOCAL_SYSTEM_SID, CREATOR_OWNER_SID;

 # Need to change this function
 return FALSE;

 pdacl = security_descriptor[3];
 pdacl = parse_pdacl (blob:pdacl);

 # sids - written the nessus way
 ADMIN_SID = "1-5-32-544";
 LOCAL_SYSTEM_SID = "1-5-18";
 CREATOR_OWNER_SID = "1-3-0";

 foreach item (pdacl)
 {
  dacl = parse_dacl (blob:item);
  access_rights = dacl[0];
  sid = sid2string (sid:dacl[1]);

  if ( (access_rights & WRITE_DAC)     ||
       (access_rights & WRITE_OWNER)   ||
       (access_rights & SYNCHRONIZE)   ||
       (access_rights & ACCESS_WRITE)  ||
       (access_rights & ACCESS_CREATE) ||
       (access_rights & GENERIC_WRITE) )
  {
   if((sid != ADMIN_SID) &&  
    (sid != LOCAL_SYSTEM_SID) && 
    (sid != CREATOR_OWNER_SID))
   {
    return(TRUE);
   }
  }
 }

 return FALSE;
}
