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

NGINX_AUTHORIZED_MODULES= attribute(
  'nginx_authorized_modules',
  description: 'List of  authorized nginx modules.',
  default: [
            "http_addition",
            "http_auth_request",
            "http_dav",
            "http_flv",
            "http_gunzip",
            "http_gzip_static",
            "http_mp4",
            "http_random_index",
            "http_realip",
            "http_secure_link",
            "http_slice",
            "http_ssl",
            "http_stub_status",
            "http_sub",
            "http_v2",
            "mail_ssl",
            "stream_realip",
            "stream_ssl",
            "stream_ssl_preread"
           ]
)
NGINX_UNAUTHORIZED_MODULES= attribute(
  'nginx_unauthorized_modules',
  description: 'List of  unauthorized nginx modules.',
  default: [
           ]
)

only_if do
  command('nginx').exist?
end

control "V-26285" do
  title "Active software modules must be minimized."

  desc "Modules are the source of nginx httpd servers core and dynamic
  capabilities. Thus not every module available is needed for operation. Most
  installations only need a small subset of the modules available. By
  minimizing the enabled modules to only those that are required, we reduce
  the number of doors and have therefore reduced the attack surface of the web
  site. Likewise having fewer modules means less software that could have
  vulnerabilities."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA00500"
  tag "gid": "V-26285"
  tag "rid": "SV-33215r1_rule"
  tag "stig_id": "WA00500 A22"
  tag "nist": ["CM-2", "Rev_4"]

  tag "check": "Enter the following command:

  nginx -V

  This will provide a list of the loaded modules. Validate that all displayed
  modules are required for operations. If any module is not required for
  operation, this is a finding.

  Note:  The following modules are needed for basic web function and do not need
  to be reviewed:

  ngx_http_* modules, except for modules excluded in the following rules below"

  tag "fix": "Disable any modules that are not needed.

  Use the configure script (available in the nginx download package) to exclude
  modules using the --without {module_name} option to reject unneeded modules."

  # START_DESCRIBE V-26285
  describe nginx do
    its('modules') { should be_in NGINX_AUTHORIZED_MODULES }
  end

  describe nginx do
    its('modules') { should_not be_in NGINX_UNAUTHORIZED_MODULES }
  end
  # STOP_DESCRIBE V-26285

end
