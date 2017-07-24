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

control "V-26368" do
  title "Automatic directory indexing must be disabled."

  desc "The ngx_http_autoindex_module module processes requests ending with the
  slash character (‘/’) and produces a directory listing. Usually a request is
  passed to the ngx_http_autoindex_module module when the
  ngx_http_index_module module cannot find an index file. To an attacker, this
  can reveal files and subdirectory names giving clues as to the type or
  configuration of the nginx server, or information not intended to be
  presented."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA00515"
  tag "gid": "V-26368"
  tag "rid": "SV-33219r1_rule"
  tag "stig_id": "WA00515 A22"
  tag "nist": ["CM-2", "Rev_4"]

  tag "check": "Enter the following command:

  nginx -V

  This will provide a list of all loaded modules.If the following module is
  found, this is a finding.

  ngx_autoindex_module"

  tag "fix": "Disable any modules that are not needed.

  Use the configure script (available in the nginx download package) to exclude
  modules using the --without {module_name} option to reject unneeded modules."

  # START_DESCRIBE V-26368
  describe nginx_module(nginx_path:NGINX_PATH, module_name:'ngx_autoindex') do
    it { should_not be_loaded }
  end
  # STOP_DESCRIBE V-26368
end
