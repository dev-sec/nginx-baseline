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

NGINX_BACKUP_REPOSITORY= attribute(
  'nginx_backup_repository',
  description: 'Path for the nginx home directory',
  default: "/usr/share/nginx/html"
)

only_if do
  command('nginx').exist?
end

control "V-2230" do

  title "Backup interactive scripts on the production web server are prohibited."

  desc  "Copies of backup files will not execute on the server, but they can
  be read by the anonymous user if special precautions are not taken. Such
  backup copies contain the same sensitive information as the actual script
  being executed and, as such, are useful to malicious users. Techniques and
  systems exist today that search web servers for such files and are able to
  exploit the information contained in them."

  impact 0.3
  tag "severity": "low"
  tag "gtitle": "WG420"
  tag "gid": "V-2230"
  tag "rid": "SV-6930r1_rule"
  tag "stig_id": "WG420 A22"
  tag "nist": ["CM-6", "Rev_4"]

  tag "check": "Search for backup copies of CGI scripts on the web server or
  ask the SA or the Web Administrator if they keep backup copies of CGI
  scripts on the web server.

  Common backup file extensions are: *.bak, *.old, *.temp, *.tmp, *.backup, .?*

  Commands to help find: find /nginx -name '.?*' -not -name .ht* -or -name '*~'
  -or -name '*

   find/usr/local/nginx/html/-name'.?*'-not-name.ht*-or-name'*~'-or-name'*.bak
   *'-or-name'*.old*'

  If files with these extensions are found in either the document directory or
  the home directory of the web server, this is a finding.

  If files with these extensions are stored in a repository (not in the document
  root) as backups for the web server, this is a finding.

  If files with these extensions have no relationship with web activity, such as
  a backup batch file for operating system utility, and they are not accessible
  by the web application, this is not a finding.  "

  tag "fix": "Ensure that CGI backup scripts are not left on the production
  web server."

  dirs = ['/home',NGINX_BACKUP_REPOSITORY]

  # collect root directores from nginx_conf
  if !nginx_conf(NGINX_CONF_FILE).http.nil?
    nginx_conf(NGINX_CONF_FILE).params['http'].each do |http|
      if !http['root'].nil?
        dirs.push(http['root'].join)
      end
    end
  end

  if !nginx_conf(NGINX_CONF_FILE).http.nil?
    nginx_conf(NGINX_CONF_FILE).http.each do |http|
      if !http['server'].nil?
        http['server'].each do |server|
          if !server['root'].nil?
            dirs.push(server['root'].join)
          end
          if !server['location'].nil?
            server['location'].each do |location|
              if !location['root'].nil?
                dirs.push(location['root'].join)
              end
            end
          end
        end
      end
    end
  end


  dirs.each do |dir|
    describe command("find #{dir} -name *.bak").stdout.chomp.split do
      it {should be_empty}
    end
    describe command("find #{dir} -name *.old").stdout.chomp.split do
      it {should be_empty}
    end
    describe command("find #{dir} -name *.temp").stdout.chomp.split do
      it {should be_empty}
    end
    describe command("find #{dir} -name *.tmp").stdout.chomp.split do
      it {should be_empty}
    end
    describe command("find #{dir} -name *.backup").stdout.chomp.split do
      it {should be_empty}
    end
    describe command("find #{dir} -name .?*").stdout.chomp.split do
      it {should be_empty}
    end
    describe command("find #{dir} -name *~").stdout.chomp.split do
      it {should be_empty}
    end
  end
end
