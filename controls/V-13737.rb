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

NGINX_CONF_FILE= attribute(
  'nginx_conf_file',
  description: 'Path for the nginx configuration file',
  default: "/etc/nginx/nginx.conf"
)

only_if do
  command('nginx').exist?
end

control "V-13737" do
  title "The HTTP request header fields must be limited. "

  desc "Buffer overflow attacks are carried out by a malicious attacker sending
  amounts of data that the web server cannot store in a given size buffer. The
  eventual overflow of this buffer can overwrite system memory. Subsequently
  an attacker may be able to elevate privileges and take control of the
  server. The NGINX directive ""large_client_header_buffers"" limits the
  maximum number and size of buffers used for reading large client request
  header thereby limiting the chances for a buffer overflow. "

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA000-WWA062"
  tag "gid": "V-13737"
  tag "rid": "SV-32757r1_rule"
  tag "stig_id": "WA000-WWA062 A22"
  tag "nist": ["CM-6", "Rev_4"]

  tag "check": "To view the large_client_header_buffers value enter the
  following command:

  grep ""large_client_header_buffers"" on the nginx.conf file and any separate
  included configuration files

  If the value of large_client_header_buffers is not set to 2 buffers at 1k,
  this is a finding. "

  tag "fix": "Edit the configuration file to set the
  large_client_header_buffers to 2 buffers and 1k."

  begin
    nginx_conf(NGINX_CONF_FILE).http.entries.each do |http|
      describe http.params['large_client_header_buffers'] do
        it { should cmp [['2','1k']] }
      end
    end

    nginx_conf(NGINX_CONF_FILE).servers.entries.each do |server|
      describe server.params['large_client_header_buffers'] do
        it { should cmp [['2','1k']] }
      end unless server.params['large_client_header_buffers'].nil?
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
