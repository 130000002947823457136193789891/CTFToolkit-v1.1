#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
if ( ! defined_func("localtime") ) exit(0);

# How far (in days) to warn of certificate expiry. [Hmmm, how often
# will scans be run and how quickly can people obtain new certs???]

lookahead = 60;

if (description) {
  script_id(15901);
  script_version ("$Revision: 1.3 $"); 

  name["english"] = "SSL Certificate Expiry";
  script_name(english:name["english"]);

  desc["english"] = "
This script checks expiry dates of certificates associated with
SSL-enabled services on the target and reports whether any have
already expired or will expire within " + lookahead + " days.

*****  Nessus relies on the clock setting on the Nessus server
*****  to determine if expiry dates are out of range. If that's
*****  inaccurate, the scan results may be as well.";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks SSL certificate expiry";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "General";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "global_settings.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");


# This function converts a date expressed as:
#   Year(2)|Month(2)|Day(2)|Hour(2)|Min(2)|Sec(2)
# and returns it in a more human-friendly format.
function x509time_to_gtime(x509time) {
  local_var mons, parts, gtime;
  mons = "JanFebMarAprMayJunJulAugSepOctNovDec";

  if (x509time && x509time =~ "^[0-9]{12}Z?$") {
    for (i=0; i<= 6; ++i) {
      parts[i] = substr(x509time, i*2, i*2+1);
    }

    if (parts[0] =~ "^9") year = string("19", parts[0]);
    else year = string("20", parts[0]);

    mm = int(parts[1]);
    if (mm >= 1 && mm <= 12) {
      --mm;
      mon = substr(mons, mm*3, mm*3+2);
    }
    else {
      mon = "unk";
    }
    parts[2] = str_replace(string:parts[2], find:"0", replace:" ");

    gtime = string(
      mon, " ", 
      parts[2], " ", 
      parts[3], ":", parts[4], ":", parts[5], " ", 
      year, " GMT"
    );
  }
  return gtime;
}


host = get_host_name();
port = get_kb_item("Transport/SSL");
if (!port || !get_port_state(port)) exit(0);
if (debug_level) display("debug: checking SSL certificate on ", host, ":", port, ".\n");

if ( debug_level ) display("getting cert.\n");
cert = get_server_cert(port:port, encoding:"der");
if (!isnull(cert)) {

  # nb: maybe someday I'll actually *parse* ASN.1.
  v = stridx(cert, raw_string(0x30, 0x1e, 0x17, 0x0d));
  if (v >= 0) {
    v += 4;
    valid_start = substr(cert, v, v+11);
    v += 15;
    valid_end = substr(cert, v, v+11);

    if (valid_start =~ "^[0-9]{12}$" && valid_end =~ "^[0-9]{12}$") {
      # Get dates, expressed in UTC, for checking certs.
      # - right now.
      tm = localtime(unixtime(), utc:TRUE);
      now = substr(string(tm["year"]), 2);
      foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
        if (tm[field] < 10) now += "0"; 
        now += tm[field];
      }
      # - 'lookahead' days in the future.
      tm = localtime(unixtime() + lookahead*24*60*60, utc:TRUE);
      future = substr(string(tm["year"]), 2);
      foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
        if (tm[field] < 10) future += "0"; 
        future += tm[field];
      }
      if (debug_level) {
        display("debug: now:    ", now, ".\n");
        display("debug: future: ", future, ".\n");
      }

      valid_start_alt = x509time_to_gtime(x509time:valid_start);
      valid_end_alt = x509time_to_gtime(x509time:valid_end);
      if (debug_level) {
        display("debug: valid not before: ", valid_start_alt, " (", valid_start, "Z).\n");
        display("debug: valid not after:  ", valid_end_alt,   " (", valid_end, "Z).\n");
      }
      if (log_verbosity > 1) display("The SSL certificate on ", host, ":", port, " is valid between ", valid_start_alt, " and ", valid_end_alt, ".\n");

      if (valid_start > now) {
        security_note(
          data:string("The SSL certificate of the remote service is not valid before ", valid_start_alt, "!"),
          port:port
        );
      }
      else if (valid_end < now) {
        security_warning(
          data:string("The SSL certificate of the remote service expired ", valid_end_alt, "!"),
          port:port
        );
      }
      else if (valid_end < future) {
        security_note(
          data:string("The SSL certificate of the remote service will expire within ", lookahead, " days, at ", valid_end_alt, "."),
          port:port
        );
      }
    }
  }
}
