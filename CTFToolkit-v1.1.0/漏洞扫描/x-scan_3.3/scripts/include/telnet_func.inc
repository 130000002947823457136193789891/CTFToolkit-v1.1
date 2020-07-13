# -*- Fundamental -*-
#
# (C) 2002 Michel Arboi <arboi@alussinan.org>
# $Revision: 1.8 $

function get_telnet_banner(port)
{
  local_var sb, banner, soc;
  sb = string("telnet/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);

  soc = open_sock_tcp(port);
  if(!soc) return (0);
  banner = telnet_init(soc);
  close(soc);
  if(strlen(banner)){
	if ( defined_func("replace_kb_item") )
		replace_kb_item(name: sb, value: banner);
	else
		set_kb_item(name: sb, value: banner);
	}
  return(banner);
}

function set_telnet_banner(port, banner)
{
  local_var sb;
  sb = string("telnet/banner/", port);
  if ( defined_func("replace_kb_item") )
  	replace_kb_item(name: sb, value: banner);
  else
  	set_kb_item(name: sb, value: banner);
}
