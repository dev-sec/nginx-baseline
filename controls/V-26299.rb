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

only_if do
  command('nginx').exist?
end

control "V-26299" do
  title "The web server must not be configured as a proxy server."

  desc "The ngx_http_proxy_module allow the server to act as a proxy (either
  forward or reverse proxy) of http and other protocols with additional proxy
  modules loaded. If the nginx installation is not intended to proxy requests
  to or from another network then the proxy module should not be loaded. Proxy
  servers can act as an important security control when properly configured,
  however a secure proxy server is not within the scope of this STIG. A web
  server should be primarily a web server or a proxy server but not both, for
  the same reasons that other multi-use servers are not recommended. Scanning
  for web servers that will also proxy requests is a very common attack, as
  proxy servers are useful for anonymizing attacks on other servers, or
  possibly proxying requests into an otherwise protected network."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA00520"
  tag "gid": "V-26299"
  tag "rid": "SV-33220r1_rule"
  tag "stig_id": "WA00520 A22"
  tag "nist": ["AC-3", "Rev_4"]

  tag "check": "Enter the following command:

  nginx -V

  This will provide a list of all loaded modules.  If the following module is
  found, this is a finding.

  ngx_http_proxy_module"

  tag "fix": "Disable any modules that are not needed.

  Use the configure script (available in the nginx download package) to exclude
  modules using the --without {module_name} option to reject unneeded modules."

  # START_DESCRIBE V-26299
  describe nginx do
    its('modules') { should_not include 'ngx_http_proxy' }
  end
  # STOP_DESCRIBE V-26299
end
