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

control "V-13736" do
  title "The HTTP request message body size must be limited."

  desc"Buffer overflow attacks are carried out by a malicious attacker sending
  amounts of data that the web server cannot store in a given size buffer. The
  eventual overflow of this buffer can overwrite system memory. Subsequently
  an attacker may be able to elevate privileges and take control of the
  server. The NGINX directive ""client_body_buffer_size"" and
  ""client_max_body_size"" limits the size of the client request body buffer
  and body content respectively, thereby limiting the chances for a buffer
  overflow. "

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA000-WWA060"
  tag "gid": "V-13736"
  tag "rid": "SV-32756r1_rule"
  tag "stig_id": "WA000-WWA060 A22"
  tag "nist": ["CM-6", "Rev_4"]

  tag "check": "To view the client_body_buffer_size value enter the following
  command:

  grep ""client_body_buffer_size"" on the nginx.conf file and any separate
  included configuration files

  grep ""client_max_body_size"" on the nginx.conf file and any separate included
  configuration files

  If the values of each are not set to 100k or less, this is a finding. "


  tag "fix": "Edit the configuration file to set the client_body_buffer_size
  and client_max_body_size to 100k or less."

  begin
    nginx_conf(NGINX_CONF_FILE).http.entries.each do |http|
      describe http.params['client_body_buffer_size'] do
        it { should_not be_nil}
      end
      describe http.params['client_body_buffer_size'].join.to_i do
        it { should cmp <= '100k'.to_i }
      end unless http.params['client_body_buffer_size'].nil?

      describe http.params['client_max_body_size'] do
        it { should_not be_nil}
      end
      describe http.params['client_max_body_size'].join.to_i do
        it { should cmp <= '100k'.to_i }
      end unless http.params['client_max_body_size'].nil?
    end

    nginx_conf(NGINX_CONF_FILE).servers.entries.each do |server|
      describe server.params['client_body_buffer_size'].join.to_i do
        it { should cmp <= '100k'.to_i }
      end unless server.params['client_body_buffer_size'].nil?

      describe server.params['client_max_body_size'].join.to_i do
        it { should cmp <= '100k'.to_i }
      end unless server.params['client_max_body_size'].nil?
    end

    nginx_conf(NGINX_CONF_FILE).locations.entries.each do |location|
      describe location.params['client_body_buffer_size'].join.to_i do
        it { should cmp <= '100k'.to_i }
      end unless location.params['client_body_buffer_size'].nil?

      describe location.params['client_max_body_size'].join.to_i do
        it { should cmp <= '100k'.to_i }
      end unless location.params['client_max_body_size'].nil?
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end

end
