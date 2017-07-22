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
  description: 'define path for the nginx configuration file',
  default: "/etc/nginx/nginx.conf"
)

only_if do
  command('nginx').exist?
end

options = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/
}

options_add_header = {
  assignment_regex: /^\s*([^:]*?)\s*\ \s*(.*?)\s*;$/,
  multiple_values: true
}

control "V-6724" do
  title "Web server and/or operating system information must be protected."

  desc "The web server response header of an HTTP response can contain several
  fields of information including the requested HTML page. The information
  included in this response can be web server type and version, operating
  system and version, and ports associated with the web server. This provides
  the malicious user valuable information without the use of extensive
  tools."

  impact 0.3
  tag "severity": "low"
  tag "gtitle": "WG520"
  tag "gid": "V-6724"
  tag "rid": "SV-36672r1_rule"
  tag "stig_id": "WG520 A22"
  tag "nist": ["CM-6", "Rev_4"]

  tag "Enter the following command:

  grep ""server_tokens"" on the nginx.conf file and any separate included
  configuration files

  The Directive server_tokens must be set to ""off"" (ex. server_tokens off;).
  This directive disables emitting nginx version on error pages and in the
  “Server” response header field.

  If the web server or operating system information are sent to the client via
  the server response header or the directive does not exist, this is a finding.

  Note: The default value is set to on."

# START_DESCRIBE V-6724

  nginx_conf(NGINX_CONF_FILE).params['http'].each do |http|
    describe http['server_tokens'] do
      it { should cmp [['off']] }
    end
  end

  if !nginx_conf(NGINX_CONF_FILE).http.nil?
    nginx_conf(NGINX_CONF_FILE).http.each do |http|
      if !http['server'].nil?
        http['server'].each do |server|
          if !server['server_tokens'].nil?
            describe server['server_tokens'] do
              it { should cmp [['off']] }
            end
          end
          if !server['location'].nil?
            server['location'].each do |location|
              if !location['server_tokens'].nil?
                describe location['server_tokens'] do
                  it { should cmp [['off']] }
                end
              end
            end
          end
        end
      end
    end
  end
# STOP_DESCRIBE V-6724
end
