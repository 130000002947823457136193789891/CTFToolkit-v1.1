# (C) 2003 Tenable Network Security
# $Id


# This function generates an SSL / TLS Client Hello message. For specs, see:
#   - http://wp.netscape.com/eng/security/SSL_2.html (SSLv2)
#   - http://wp.netscape.com/eng/ssl3/draft302.txt (SSLv3)
#   - http://www.ietf.org/rfc/rfc2246.txt (TLSv1)
#
# Args:
#   o mlen = message length after this byte; 1 byte.
#   o mtype = handshake message type; 1 byte.
#     nb: 0x01 => Client Hello (default).
#   o version = client SSL version; 2 bytes.
#     nb: 0x0002 => SSLv2, 0x0300 => SSLv3 (default), 0x0301 => TLSv1.
#   o v2hello = whether to use v2 client hello format.
#     nb: FALSE (use protocol-specific format), TRUE (default).
#   o cipherspec = which ciphers are supported.
#   o cspeclen = cipher spec len; 2 bytes.
#   o sessionid = session ID (defaults to empty string
#     or random bytes if sessionidlen is non-zero).
#   o sessionidlen = session ID length; 2 bytes for SSLv2, 1 byte otherwise.
#   o challenge = random bytes of challenge data.
#     nb: for SSLv2, defaults to "NESSUSNESSUSNESS";
#         for SSLv3 or TLSv1, defaults to current unix datetime
#         followed by "NESSUSNESSUSNESSUSNESSUSNESS".
#   o challengelen = length of challenge; 2 bytes.
#     nb: this is used only with SSLv2 format hellos.
#   o compmeths = list of compression methods supported by client,
#     1 byte each (defaults to 0x00 => no compression).
#     nb: this is not used with SSLv2.
#   o compmethslen = length of compression methods.
# Return:
#   o a raw string representing the Client Hello message.
#
# updated: 16-Nov-2004, George A. Theall
#
# updated: 29-Dec-2004, Tenable Network Security / jwl


function client_hello(mlen, mtype, version, v2hello, cipherspec, cspeclen, sessionid, sessionidlen, challenge, challengelen, compmeths, compmethslen) {
  local_var chello, chellolen, handshake, myhello;

  # Assign some defaults.
  if ( (mtype <= 0) || isnull(version) ) mtype = raw_string(0x01);			# set to hello packet by default
  if (isnull(version)) version = raw_string(0x03, 0x00);
  if (isnull(v2hello)) v2hello = TRUE;

  # Generate the hello.
  #
  # - SSLv2, whether it's explicitly SSLv2 or in v2 compatability mode.
  if (version == raw_string(0x00, 0x02) || v2hello == TRUE) {
    # Assign other defaults.
    #
    # - ciphers.
    if (isnull(cipherspec)) {
      if ( (isnull(cspeclen)) || (cspeclen <= 0 ) ) 
        cipherspec = 
          # TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
          raw_string(0x00, 0x00, 0x62) +
          # SSL2_RC2_CBC128_CBC_WITH_MD5
          raw_string(0x04, 0x00, 0x80) +
          # TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
          raw_string(0x00, 0x00, 0x63) +
          # TLS_RSA_EXPORT_WITH_RC4_40_MD5
          raw_string(0x00, 0x00, 0x03) +
          # TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
          raw_string(0x00, 0x00, 0x64) +
          # SSL2_RC4_128_EXPORT40_WITH_MD5
          raw_string(0x02, 0x00, 0x80);
      else 
        # nb: fill it with random bytes.
        while (strlen(cipherspec) < cspeclen)
          cipherspec = cipherspec + (rand() % 256);
    }
    if (isnull(cspeclen)) {
      cspeclen = strlen(cipherspec); 
      cspeclen = raw_string(cspeclen / 256, cspeclen % 256);
    }
    # - session ID.
    if (isnull(sessionid)) {
      if (sessionidlen) 
        # nb: fill it with random bytes.
        while (strlen(sessionid) < sessionidlen)
          sessionid = sessionid + (rand() % 256);
      else sessionid = "";
    }
    if (isnull(sessionidlen)) {
      sessionidlen = strlen(sessionid);
      sessionidlen = raw_string(sessionidlen / 256, sessionidlen % 256);
    }
    # - challenge.
    if (isnull(challenge)) challenge = "NESSUSNESSUSNESS";
    if (isnull(challengelen)) {
      challengelen = strlen(challenge);
      challengelen = raw_string(challengelen / 256, challengelen % 256);
    }

    # Assemble the message.
    # nb: 2 byte length code is used since we don't need any padding.
    handshake = mtype +
                version +
                cspeclen +
                sessionidlen +
                challengelen +
                cipherspec;
    if (sessionid) handshake = handshake + sessionid;
    handshake = handshake + challenge;
    if ( (mlen <= 0) || isnull(mlen) ) mlen = strlen(handshake);
    myhello = raw_string(0x80 | (mlen / 256), mlen % 256) + handshake;
  }
  # - SSLv3 or TLSv1.
  else if (version == raw_string(0x03, 0x00) || version == raw_string(0x03, 0x01)) {
    # Assign other defaults.
    #
    # - ciphers.
    if (isnull(cipherspec)) {
      if (isnull(cspeclen)) 
        # nb: this is what openssl s_client uses by default.
        cipherspec = 
          # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
          raw_string(0x00, 0x39) +
          # TLS_DHE_DSS_WITH_AES_256_CBC_SHA
          raw_string(0x00, 0x38) +
          # TLS_RSA_WITH_AES_256_CBC_SHA
          raw_string(0x00, 0x35) +
          # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
          raw_string(0x00, 0x16) +
          # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
          raw_string(0x00, 0x13) +
          # TLS_RSA_WITH_3DES_EDE_CBC_SHA
          raw_string(0x00, 0x0a) +
          # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
          raw_string(0x00, 0x33) +
          # TLS_DHE_DSS_WITH_AES_128_CBC_SHA
          raw_string(0x00, 0x32) +
          # TLS_RSA_WITH_AES_128_CBC_SHA
          raw_string(0x00, 0x2f) +
          # TLS_RSA_WITH_IDEA_CBC_SHA
          raw_string(0x00, 0x07) +
          # TLS_DHE_DSS_WITH_RC4_128_SHA
          raw_string(0x00, 0x66) +
          # TLS_RSA_WITH_RC4_128_SHA
          raw_string(0x00, 0x05) +
          # TLS_RSA_WITH_RC4_128_MD5
          raw_string(0x00, 0x04) +
          # TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
          raw_string(0x00, 0x63) +
          # TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
          raw_string(0x00, 0x62) +
          # TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5
          raw_string(0x00, 0x61) +
          # TLS_DHE_RSA_WITH_DES_CBC_SHA
          raw_string(0x00, 0x15) +
          # TLS_DHE_DSS_WITH_DES_CBC_SHA
          raw_string(0x00, 0x12) +
          # TLS_RSA_WITH_DES_CBC_SHA
          raw_string(0x00, 0x09) +
          # TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA
          raw_string(0x00, 0x65) +
          # TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
          raw_string(0x00, 0x64) +
          # TLS_RSA_EXPORT1024_WITH_RC4_56_MD5
          raw_string(0x00, 0x60) +
          # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
          raw_string(0x00, 0x14) +
          # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
          raw_string(0x00, 0x11) +
          # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
          raw_string(0x00, 0x08) +
          # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
          raw_string(0x00, 0x06) +
          # TLS_RSA_EXPORT_WITH_RC4_40_MD5
          raw_string(0x00, 0x03);
      else 
        # nb: fill it with random bytes.
        while (strlen(cipherspec) < cspeclen)
          cipherspec = cipherspec + (rand() % 256);
    }
    if (isnull(cspeclen)) {
      cspeclen = strlen(cipherspec);
      cspeclen = raw_string(cspeclen / 256, cspeclen % 256);
    }
    # - session ID.
    if (isnull(sessionid)) {
      if (sessionidlen) {
        # nb: fill out field with random bytes.
        while (strlen(sessionid) < sessionidlen)
          sessionid = sessionid + (rand() % 256);
      }
      else sessionid = "";
    }
    if (isnull(sessionidlen)) sessionidlen = raw_string(strlen(sessionid));
    # - challenge.
    if (isnull(challenge)) {
      challenge = dec2hex(num:unixtime()) + "NESSUSNESSUSNESSUSNESSUSNESS";
    }
    # - compression methods
    if (isnull(compmeths)) {
      compmeths = raw_string(0x00);
      # nb: fill out field with random bytes.
      while (strlen(compmeths) < compmethslen)
        compmeths = compmeths + (rand() % 256);
    }
    if (isnull(compmethslen)) compmethslen = raw_string(strlen(compmeths));

    # Assemble the message.
    chello = version +
             challenge + 
             sessionidlen + sessionid +
             cspeclen + cipherspec +
             compmethslen + compmeths;
    chellolen = strlen(chello);
    handshake = mtype +
              raw_string(0, chellolen / 256, chellolen % 256) +
              chello;
    if (isnull(mlen)) mlen = strlen(handshake);
    myhello = raw_string(0x16) +
              version +
              raw_string(mlen / 256, mlen % 256) +
              handshake;
  }

  return(myhello);
}


function client_send_cert (contenttype, version, length, hshaketype, hlength, clength, clength2, certificate) {
  # contenttype = content type (1 byte) -- handshake is 0x16
  # version = version (2 bytes) -- SSL v3 is 0x03 0x00
  # length = length (2 bytes) of record following this length field
  # hshaketype = handshake type (1 byte) -- certificate is 0x0B
  
  # Note to self:  3 bytes is a *lot* of space...

  # hlength = handshake length (3 bytes) (also equal to length - 4)
  # clength = certificate length (3 bytes) (or hlength - 3)
  # clength2 = actual cert length (3 bytes) (just subtract another 3 from clength)
  # certificate = clength2 bytes of certificate
  

  if (!certificate) exit(0);                      # must have a cert... 

  certlen = strlen(certificate);

  if (!contenttype) contenttype = raw_string(0x16);
  if (!version) version = raw_string(0x03, 0x00);
  if (!hshaketype) hshaketype = raw_string(0x0B);

  if (!clength2) {
    clength2 = certlen; 
    if (clength2 <= 0xFF) clength2 = raw_string(0x00, 0x00, clength2);
    else clength2 = raw_string(0x00, clength2 / 256, clength2 % 256); 
  }

  if (!clength) {
      tlen = certlen + 3;
      if (tlen <= 0xFF) clength = raw_string(0x00, 0x00, tlen);
      else clength = raw_string(0x00, tlen / 256, tlen % 256); 
  }

  if (!hlength) {
      tlen = certlen + 6;
      if (certlen <= 0xFF) hlength = raw_string(0x00, 0x00, tlen);
      else hlength = raw_string(0x00, tlen / 256, tlen % 256);
  }

  if (!length) {
    length = certlen + 10;
    if (length <= 0xFF) length = raw_string(0x00, strlen(length));
    else length = raw_string(length / 256, length % 256);
  }

 
    
  client_cert = contenttype + version + length + hshaketype + hlength + clength + clength2 + certificate;
  return (client_cert); 
}


# This function returns the message digest (fingerprint) of a string.
#
# Args:
#   o string - the string to fingerprint.
#   o type - the type of message digest to use, either MD5 (default) or SHA1.
#
# Return:
#   o a string of hex numbers, each separated by a colon, representing 
#     the string's fingerprint.
#
# updated: 16-Nov-2004, George A. Theall
#
function fingerprint_string(str, type) {
  local_var digest;

  if (isnull(str)) return(NULL);
  if (isnull(type)) type = "md5";

  if (type =~ "md5") {
    digest = MD5(str);
  }
  else if (type =~ "sha1") {
    digest = SHA1(str);
  }
  else {
    # unsupported digest type.
    return(NULL);
  }

  digest = ereg_replace(string:hexstr(digest), pattern:"(..)", replace:"\1:");
  digest = substr(digest, 0, strlen(digest)-2);

  return(digest);
}


# This function returns the message digest (fingerprint) of an SSL 
# certificate.
#
# Args:
#   o cert - the certificate (either PEM or DER-encoded).
#   o type - the type of digest to use, either MD5 (default) or SHA1.
#
# Return:
#   o a string of hex numbers, each separated by a colon, representing 
#     the certificate's fingerprint.
#
# updated: 16-Nov-2004, George A. Theall
#
function fingerprint_cert(cert, type) {
  local_var der;

  if (isnull(type)) type = "md5";

  # If the cert is PEM-encoded, convert it to DER-encoding.
  if (egrep(string:cert, pattern:"(BEGIN CERTIFICATE|^.{64}$)")) {
    der = "";
    foreach line (split(cert, keep:TRUE)) {
      if (line !~ "^-+(BEGIN|END) CERTIFICATE-+$") {
        der += line;
      }
    }
    cert = base64_decode(der);
  }

  return(fingerprint_string(str:cert, type:type));
}


# This function returns the server certificate for the SSL-enabled
# service on a given port.
#
# Args:
#   o port - a port number.
#   o encoding - format of certificate, either PEM (default) or DER.
#
# Return:
#   o a string representing the SSL certificate.
#
# updated: 16-Nov-2004, George A. Theall
#
function get_server_cert(port, encoding) {
  local_var cert;

  if (isnull(port)) return(NULL);
  if (isnull(encoding)) encoding = "pem";

  # Try to get cert from the KB.
  cert = get_kb_item("SSL/Certificate/" + port);

  # If that didn't work, retrieve it directly.
  if (!cert) {
    local_var buf, hello, done, encaps, hexmsg, host, soc, ssl;
    local_var msg, msg_len, msg_type;
    local_var hand, hand_len, hand_type;
    local_var cert, cert_len;
    local_var alert_desc, alert_lvl, err_code;

    host = get_host_name();
    if (!get_port_state(port)) return(NULL);
    soc = open_sock_tcp(port, transport:ENCAPS_IP);
    if (!soc) exit(0);

    encaps = get_kb_item("Transports/TCP/"+port);
	
    if (!encaps) return(NULL);
    if (debug_level) display("debug: encapsulation type is ", encaps, ".\n");
    # nb: see nessus-libraries/include/libnessus.h for defines
    #     mapping encapsulations to SSL / TLS version.
    if (encaps == 3) ssl = "SSLv2";
    else if (encaps == 4) ssl = "SSLv3";
    else if (encaps == 5) ssl = "TLSv1";
    else return(NULL);
    if (debug_level) display("debug: fingerprinting ", ssl, " certificate on ", host, ":", port, ".\n");

    # Send client hello.
    if (ssl == 'SSLv2') {
      hello = client_hello(version:raw_string(0x00, 0x02));
    }
    else if (ssl == 'SSLv3') {
      hello = client_hello(v2hello:FALSE, version:raw_string(0x03, 0x00));
    }
    else if (ssl == 'TLSv1') {
      hello = client_hello(v2hello:FALSE, version:raw_string(0x03, 0x01));
    }
    if (debug_level) {
      display("debug: sending ", ssl, " Client Hello:\n");
      hexmsg = ereg_replace(string:hexstr(hello), pattern:"(..)", replace:"0x\1 ");
      if (!hexmsg) hexmsg = "-- empty --";
      display("debug:   ", hexmsg, "\n");
    }
    send(socket:soc, data:hello);
    buf = recv(socket:soc, length:8192); 
    close(soc);

    # Process server message(s). 
    done = 0;
    if (ssl == 'SSLv2') {
      # Isolate a message.
      while (!done && strlen(buf) > 3) {
        msg_type = ord(buf[2]);
        msg_len = ((ord(buf[0]) & 0x7f) << 8) | ord(buf[1]);
        msg = substr(buf, 0, msg_len+2-1);
        if (debug_level) {
          display("debug: message type: ", msg_type, ".\n");
          display("debug:   length:     ", msg_len, ".\n");
          hexmsg = ereg_replace(string:hexstr(msg), pattern:"(..)", replace:"0x\1 ");
          if (!hexmsg) hexmsg = "-- empty --";
          display("debug:   contents:   ", hexmsg, "\n");
        }
        buf = substr(buf, msg_len);

        # Handshake message.
        if (msg_type == 4 && strlen(msg) > 14) {
          # X.509 certificate.
          if (ord(msg[4]) == 1) {
            cert_len = ord(msg[7])*256 + ord(msg[8]);
            cert = substr(msg, 13, cert_len+13-1);
            if (debug_level) {
              display("debug: cert length: ", cert_len, ".\n");
              hexmsg = ereg_replace(string:hexstr(cert), pattern:"(..)", replace:"0x\1 ");
              if (!hexmsg) hexmsg = "-- empty --";
              display("debug:   contents:  ", hexmsg, "\n");
            }
            done = 1;
          }
        }
        # Error message.
        else if (msg_type == 0 && strlen(msg) == 2) {
          err_code = ord(msg[1]) * 256 + ord(msg[1]);
          if (debug_level) display("debug: error code: ", err_code, "\n");
        }
        # Something else.
        else {
          if (log_verbosity > 1) display("Message of type ", msg_type, " received from ", host, ":", port, "!\n");
        }
        if (debug_level) display("debug:\n");
      }
    }
    else if (ssl == 'SSLv3' || ssl == 'TLSv1') {
      # We *should* see the Server Hello handshake first, followed by the Server
      # Certificate handshake, but not depending on the order is more robust.
      while (!done && strlen(buf) > 5) {
        msg_type = ord(buf[0]);
        msg_len = ord(buf[3])*256 + ord(buf[4]);
        # nb: msg_len doesn't include the first 5 bytes.
        msg = substr(buf, 0, msg_len+5-1);
        if (debug_level) {
          display("debug: message type: ", msg_type, ".\n");
          display("debug:   length:     ", msg_len, ".\n");
          hexmsg = ereg_replace(string:hexstr(msg), pattern:"(..)", replace:"0x\1 ");
          if (!hexmsg) hexmsg = "-- empty --";
          display("debug:   contents:   ", hexmsg, "\n");
        }
        buf = substr(buf, msg_len+5);

        # Handshake message.
        if (msg_type == 22 && strlen(msg) > 3) {
          while (!done && strlen(msg) > 8) {
            hand_type = ord(msg[5]);
            hand_len = ord(msg[6])*65536 + ord(msg[7])*256 + ord(msg[8]);
            # nb: hand_len doesn't include the first 4 bytes.
            hand = substr(msg, 5, hand_len+4+5-1);
            if (debug_level) {
              display("debug: handshake type: ", hand_type, ".\n");
              display("debug:   length:       ", hand_len, ".\n");
              hexmsg = ereg_replace(string:hexstr(hand), pattern:"(..)", replace:"0x\1 ");
              if (!hexmsg) hexmsg = "-- empty --";
              display("debug:   contents:     ", hexmsg, "\n");
            }

            # Certificate handshake.
            if (hand_type == 11 && strlen(hand) > 7) {
              # First cert belongs to the server itself.
              cert_len = ord(hand[7])*65536 + ord(hand[8])*256 + ord(hand[9]);
              cert = substr(hand, 10, cert_len+10-1);
              if (debug_level) {
                display("debug: cert length: ", cert_len, ".\n");
                hexmsg = ereg_replace(string:hexstr(cert), pattern:"(..)", replace:"0x\1 ");
                if (!hexmsg) hexmsg = "-- empty --";
                display("debug: server cert: ", hexmsg, "\n");
              }
              done = 1;
            }
            msg = substr(msg, hand_len+4);
          }
        }
        # Alert message.
        else if (msg_type == 21 && strlen(msg) == 2) {
          alert_lvl = ord(msg[0]);
          alert_desc = ord(msg[1]);
          if (debug_level) {
            display("debug: alert level: ", alert_lvl, "\n");
            display("debug:   desc:      ", alert_desc, "\n");
          }
        }
        # Something else.
        else {
          if (log_verbosity > 1) display("Non-handshake message of type ", msg_type, " received from ", host, ":", port, "!\n");
        }
        if (debug_level) display("debug:\n");
      }
    }

    if (done) {
      cert = string(
        "-----BEGIN CERTIFICATE-----\n",
        ereg_replace(
          string:base64(str:cert),
          pattern:"(.{64})", 
          replace:"\1" + raw_string("\n")
        ),
        "\n",
        "-----END CERTIFICATE-----\n"
      );

      set_kb_item(name:"SSL/Certificate/" + port, value:cert);
    }
    else {
      # The port was open but we couldn't get the certificate for some reason
      # so let the user know if we're verbosely logging.
      if (log_verbosity > 1) display("Can't get SSL certificate on ", host, ":", port, "!\n");
      return(NULL);
    }
  }

  if (encoding =~ "der") {
    local_var der, line;
    der = "";
    foreach line (split(cert, keep:FALSE)) {
      if (line !~ "^-+(BEGIN|END) CERTIFICATE-+$") {
        der += line;
      }
    }
    return(base64_decode(str:der));
  }
  else if (encoding =~ "pem") {
    return(cert);
  }
  else {
    # unsupported encoding.
    return(NULL);
  }
}
