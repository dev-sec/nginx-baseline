# encoding: utf-8 
# 
=begin 
----------------- 
Benchmark: APACHE SERVER 2.2 for Unix  
Status: Accepted 

All directives specified in this STIG must be specifically set (i.e. the
server is not allowed to revert to programmed defaults for these directives).
Included files should be reviewed if they are used. Procedures for reviewing
included files are included in the overview document. The use of .htaccess
files are not authorized for use according to the STIG. However, if they are
used, there are procedures for reviewing them in the overview document. The
Web Policy STIG should be used in addition to the Apache Site and Server STIGs
in order to do a comprehensive web server review.

Release Date: 2015-08-28 
Version: 1 
Publisher: DISA 
Source: STIG.DOD.MIL 
uri: http://iase.disa.mil 
----------------- 
=end 

control "V-new" do

  title "The web server must restrict SSL protocols."
  
  desc "During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference.  The web server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours."
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG345"
  tag "gid": "V-60707"
  tag "rid": "SV-75159r1_rule"
  tag "stig_id": "WG345 A22"
  tag "nist": ["SC-8", "Rev_4"]
  
  tag "check": "Review the nginx.conf file and any separate included configuration files.  

Ensure the following entry exists:

server {
       # SSL protocols TLS v1~TLSv1.2 are allowed. Disabed SSLv3
       ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
}

If the entry is not found, this is a finding."
  
  tag "fix": "Review the nginx.conf file and any separate included
  configuration files.

  Edit to ensure the following entry exists:

  server {
         # SSL protocols TLS v1~TLSv1.2 are allowed. Disabed SSLv3
         ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  }
  "

  # START_DESCRIBE V-60707
  # STOP_DESCRIBE V-60707

end
