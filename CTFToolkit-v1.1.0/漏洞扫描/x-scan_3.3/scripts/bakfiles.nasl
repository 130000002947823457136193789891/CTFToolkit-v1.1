# Written by Renaud Deraison <deraison@nessus.org>
#
#
# This plugin uses the data collected by webmirror.nasl to try
# to download a backup file old each CGI (as in foo.php -> foo.php.old)


if(description)
{
 script_id(11411);
 script_version ("$Revision: 1.12 $");
 
 name["english"] = "Backup CGIs download";
 script_name(english:name["english"]);
 
 desc["english"] = "
This script attempts to download a backup file of each
CGI by doing a GET request on the name of each CGI, followed by
a .bak, ~ or .old.";



 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to download the remote CGIs";
 
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

list = make_list();

t = get_kb_list(string("www/", port, "/cgis"));
if(!isnull(t)){
	foreach c (t)
	s = strstr(c, " - ");
	c = c - s;
	list = make_list(list, c);
	}


t = get_kb_list(string("www/", port, "/content/extensions/asp"));
if(!isnull(t))list = make_list(list, t);

t = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if(!isnull(t))list = make_list(list, t);

t = get_kb_list(string("www/", port, "/content/extensions/php"));
if(!isnull(t))list = make_list(list, t);

t = get_kb_list(string("www/", port, "/content/extensions/php3"));
if(!isnull(t))list = make_list(list, t);

t = get_kb_list(string("www/", port, "/content/extensions/php4"));
if(!isnull(t))list = make_list(list, t);

t = get_kb_list(string("www/", port, "/content/extensions/cfm"));
if(!isnull(t))list = make_list(list, t);


list = make_list(list, "/.htaccess");


exts = make_list(".old", ".bak", "~", ".2", ".copy", ".tmp", ".swp", ".swp");
prefixes = make_list("", "",   "",  "",   "",      "",     "",      ".");

oldfiles = make_list();
foreach f (list)
{
 this_oldfiles = make_list();
 num_match = 0;
 for ( i = 0; exts[i]; i ++ )
 {
   file = ereg_replace(pattern:"(.*)/([^/]*)$", replace:"\1/" + prefixes[i] + "\2" + exts[i], string:f);
   if(is_cgi_installed_ka(port:port, item:file))
   {
     this_oldfiles = make_list(this_oldfiles, file);
     num_match ++;
   }
 }
 # Avoid false positives
 if(num_match < 5) oldfiles = make_list(oldfiles, this_oldfiles);
}

report = NULL;

foreach f (oldfiles)
{
  report += f + '\n';
}

if( report != NULL )
  {
    report = "
It seems that the source code of various CGIs can be accessed by 
requesting the CGI name with a special suffix (.old, .bak, ~ or .copy)

Here is the list of CGIs Nessus gathered :
" + report + '\n\nYou should delete these files.';

  security_hole(port:port, data:report);

  }
