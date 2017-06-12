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

control "V-26287" do
  title "Web Distributed Authoring and Versioning (WebDAV) must be disabled."
  
  desc "Ngx_http_dav_module supports WebDAV ('Web-based Distributed Authoring
  and Versioning') functionality for nginx. WebDAV is an extension to the HTTP
  protocol which allows clients to create, move, and delete files and
  resources on the web server. WebDAV is not widely used, and has serious
  security concerns as it may allow clients to modify unauthorized files on
  the web server. Therefore, the WebDav module ngx_http_dav_module should be
  disabled."
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA00505"
  tag "gid": "V-26287"
  tag "rid": "SV-33216r1_rule"
  tag "stig_id": "WA00505 A22"
  tag "nist": ["AC-3", "Rev_4"]
  
  tag "check": "Enter the following command:

  nginx -V

  This will provide a list of all loaded modules.  If the following module is
  found, this is a finding.

  ngx_http_dav_module"

  tag "fix": "Disable any modules that are not needed.

  Use the configure script (available in the nginx download package) to exclude
  modules using the --without {module_name} option to reject unneeded modules."

  # START_DESCRIBE V-26287
  # STOP_DESCRIBE V-26287
end
