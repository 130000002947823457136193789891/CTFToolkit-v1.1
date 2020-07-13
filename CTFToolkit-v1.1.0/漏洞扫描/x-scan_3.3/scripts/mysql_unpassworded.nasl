#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

#
# Complete rewrite to make it more compatible throughout the versions of MySQL
# Noam Rathaus
#

if(description)
{
 
 script_id(10481);  
 script_version ("$Revision: 1.26 $");
 script_cve_id("CAN-2004-1532");
 script_bugtraq_id(11704);

 name["english"] = "Unpassworded MySQL";
 name["francais"] = "MySQL sans mot de passe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This script attempts to log into to the remote
MySQL daemon, and retrieves the list of the
databases installed on the remote host.

Risk factor : High";

	
 desc["francais"] = "
Ce script tente de se logguer dans le daemon MySQL distant
et d'en obtenir la liste des bases qu'il gère.";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to log into the remote MySQL daemon";
 summary["francais"] = "Tente de se logger dans le daemon MySQL distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

include("dump.inc");

debug = 0; # darn inconsistant results flaky msql servers?
port = get_kb_item("Services/mysql");
if(!port)port = 3306;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
r1 = recv(socket:soc, length:1024);
if(strlen(r1) < 7)exit(0);
if (" is not allowed to connect to this MySQL" >< r1) exit(0);
if ("Access denied" >< r1)exit(0);
if ("is blocked because of many connection errors" >< r1) {
 # security_note(port:port, data:'This MySQL server is temporarily refusing connections.\n');
  exit(0);
}

str = raw_string(0x0A, 0x00, 0x00, 0x01, 0x85, 0x04,
    	 	 0x00, 0x00, 0x80, 0x72, 0x6F, 0x6F, 0x74, 0x00);

send(socket:soc, data:str);
r1 = recv(socket:soc, length:4096);

if (debug)
{
 dump(dtitle: "r1", ddata: r1);
}

if(!strlen(r1))exit(0);

packetlen = ord(r1[0]) + ord(r1[1])*256 + ord(r1[2])*256*256 - 1; # Packet Length of 1 is actually 0
packetnumber = ord(r1[3]);
responsecode = ord(r1[4]);
payload = substr(r1, 5, 5+packetlen-1);

if (debug)
{
 display("packetlen: ", packetlen, " packetnumber: ", packetnumber, " responsecode: ", responsecode, "\n");
 dump(dtitle: "payload", ddata: payload);
}

if (responsecode == 255)
{
 errorcode = ord(r1[5]) + ord(r1[6])*256;
 payload = substr(r1, 7, 7+packetlen-1);

if (debug)
 {
  display("errorcode: ", errorcode, "\n");
  dump(dtitle: "payload", ddata: payload);
 }

 # ErrorCode 255 is access denied
 close(soc);
 exit(0);
}

#
# Ask the databases
#
str = raw_string(0x0F, 0x00, 0x00, 0x00, 0x03) + "show databases";
send(socket:soc, data:str);
r = recv(socket:soc, length:2048);
close(soc);

if (debug)
{
 dump(dtitle: "r", ddata: r);
 display("strlen(r): ", strlen(r), "\n");
}

pos = 0;
dbs = "";
ok = 1;
Database_response = 0;
Database_capture = 0;
skip = 0;

while(ok)
{
 skip = 0;
 
 if (debug)
 {
  display("pos: ", pos, "\n");
 }
 
 packetlen = ord(r[pos]) + ord(r[pos+1])*256 + ord(r[pos+2])*256*256 - 1; # Packet Length is 1 is actually 0 bytes
 packetnumber = ord(r[pos+3]);
 responsecode = ord(r[pos+4]);
 payload = substr(r, pos+5, pos+5+packetlen-1);

 if (debug)
 {
  display("packetlen: ", packetlen, " packetnumber: ", packetnumber, " responsecode: ", responsecode, "\n");
  dump(dtitle: "payload", ddata: payload);
 }

 if ((!skip) && (responsecode == 254) && (Database_capture == 1))
 {
  skip = 1;
  Database_capture = 0;
  if (debug)
  {
   display("Stopped capturing DBS\n");
  }
 }

 if ((!skip) && (responsecode == 254) && (Database_capture == 0))
 {
  skip = 1;
  Database_capture = 1;
  if (debug)
  {
   display("Capuring DBS\n");
  }
 }
     
 if ((!skip) && (payload >< "Database") && (responsecode == 0))
 {
  skip = 1;
  if (debug)
  {
   display("Found Database list\n");
  }
  Database_response = 1;
 }

 if ((!skip) && Database_capture)
 {
  if (debug)
  {
   display("payload (dbs): ", payload, "\n");
  }
  if (dbs)
  {
   dbs = string(dbs, ", ", payload);
  }
  else
  {
   dbs = payload;
  }
 }
 
 pos = pos + packetlen + 5;
 if (pos >= strlen(r))
 {
  ok = 0;
 }
}


report = string("Your MySQL database is not password protected.\n\n",
"Anyone can connect to it and do whatever he wants to your data\n",
"(deleting a database, adding bogus entries, ...)\n",
"We could collect the list of databases installed on the remote host :\n\n",
dbs,
"\n",
"Solution : Log into this host, and set a password for the root user\n",
"through the command 'mysqladmin -u root password <newpassword>'\n",
"Read the MySQL manual (available on www.mysql.com) for details.\n",
"In addition to this, it is not recommended that you let your MySQL\n",
"daemon listen to request from anywhere in the world. You should filter\n",
"incoming connections to this port.\n\n",
"Risk factor : High");

security_hole(port:port, data:report);

