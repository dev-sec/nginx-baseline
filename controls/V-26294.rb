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

NGINX_PATH= attribute(
  'nginx_path',
  description: 'Path for the nginx configuration file',
  default: "/usr/sbin/nginx"
)

control "V-26294" do
  title "Web server status module must be disabled."

  desc "The ngx_http_status_module provides configuration information on
  thecurrent server and performance statistics. While having server
  configuration and status information available as a web page may be
  convenient, it is recommended that these modules not be enabled."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA00510"
  tag "gid": "V-26294"
  tag "rid": "SV-33218r1_rule"
  tag "stig_id": "WA00510 A22"
  tag "nist": ["AC-3", "Rev_4"]

  tag "check": "Enter the following command:

  nginx -V

  This will provide a list of all loaded modules.  If the following module is
  found, this is a finding.

  ngx_http_status_module"

  tag "fix": "Disable any modules that are not needed.

  Use the configure script (available in the nginx download package) to exclude
  modules using the --without {module_name} option to reject unneeded modules."

  # START_DESCRIBE V-26294

  describe nginx_module(nginx_path:NGINX_PATH, module_name:'ngx_http_status') do
    it { should_not be_loaded }
  end

  # STOP_DESCRIBE V-26294

end
