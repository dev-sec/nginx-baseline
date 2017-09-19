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

control "V-13735" do
  title "Directory indexing must be disabled on directories not containing index files."

  desc"autoindex and random_index directives can be applied to further
  restrict access to file and directories.If a URL which maps to a directory
  is requested, and there is no DirectoryIndex (e.g., index.html) in that
  directory, then enabling these directives will return a formatted listing of
  the directory which is not acceptable.

  autoindex enables or disables the directory listing output. The
  ngx_http_random_index_module module processes requests ending with the slash
  character (‘/’) and picks a random file in a directory to serve as an index
  file. The module is processed before the ngx_http_index_module module."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA000-WWA058"
  tag "gid": "V-13735"
  tag "rid": "SV-32755r1_rule"
  tag "stig_id": "WA000-WWA058 A22"
  tag "nist": ["CM-6", "Rev_4"]

  tag "check": "To view the autoindex and random_index values enter the
  following commands:

  grep ""autoindex"" on the nginx.conf file and any separate included
  configuration files

  grep ""random_index"" on the nginx.conf file and any separate included
  configuration files

  If the values of each are not set to off, this is a finding:

  autoindex off;

  random_index off;"

  tag "fix": "Edit the configuration file and set the values to off:

  autoindex off;

  random_index off;"

  begin
    nginx_conf_handle = nginx_conf(NGINX_CONF_FILE)

    nginx_conf_handle.http.entries.each do |http|
      describe http.params['autoindex'] do
        it { should cmp [['off']] }
      end
    end

    nginx_conf_handle.servers.entries.each do |server|
      describe server.params['autoindex'] do
        it { should cmp [['off']] }
      end unless server.params['autoindex'].nil?
    end

    nginx_conf_handle.locations.entries.each do |location|
      describe location.params['autoindex'] do
        it { should cmp [['off']] }
      end unless location.params['autoindex'].nil?
      describe location.params['random_index'] do
        it { should cmp [['off']] }
      end
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end

end
