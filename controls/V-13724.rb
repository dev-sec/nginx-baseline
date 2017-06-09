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

options = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/
}

control "V-13724" do
  title "The client body and header timeout directives must be properly set."

  desc "The timeout requirements are set to mitigate the effects of several
  types of denial of service attacks. Although there is some latitude
  concerning the settings themselves, the requirements attempt to provide
  reasonable limits for the protection of the web server. If necessary, these
  limits can be adjusted to accommodate the operational requirement of a given
  system.

  client_body_timeout defines a timeout for reading client request body. The
  timeout is set only for a period between two successive read operations, not
  for the transmission of the whole request body. If a client does not transmit
  anything within this time, the 408 (Request Time-out) error is returned to the
  client.

  client_header_timeout defines a timeout for reading client request header. If
  a client does not transmit the entire header within this time, the 408
  (Request Time-out) error is returned to the client. "
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA000-WWA020"
  tag "gid": "V-13724"
  tag "rid": "SV-32977r1_rule"
  tag "stig_id": "WA000-WWA020 A22"
  tag "nist": ["CM-6", "Rev_4"]
  
  tag "check": "To view the timeout values enter the following commands:

  grep ""client_body_timeout"" on the nginx.conf file and any separate included
  configuration files

  grep ""client_header_timeout"" on the nginx.conf file and any separate
  included configuration files

  If the values of each are not set to 10 seconds (10s) or less, this is a
  finding."


  tag "fix": "Edit the configuration file and set the value of 10 seconds or
  less:

  client_body_timeout   10s;

  client_header_timeout 10s;"

  describe parse_config_file(NGINX_CONF_FILE, options) do
    its('client_body_timeout') { should eq '10' }
  end
  describe parse_config_file(NGINX_CONF_FILE, options) do
    its('client_header_timeout') { should eq '10' }
  end

end
