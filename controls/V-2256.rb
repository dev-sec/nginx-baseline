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

WEB_MANAGER = attribute(
  'web_manager',
  description: "The web manager",
  default: 'nginx_web_manager'
)

SYS_ADMIN = attribute(
  'sys_admin',
  description: "The system adminstrator",
  default: 'nginx_sys_admin'
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

access_control_files= [ ".htaccess",
                        ".htpasswd"
                      ]

control "V-2256" do
  title "The access control files are owned by a privileged web server account."
  
  desc " This check verifies that the key web server system configuration files
  are owned by the SA or Web Manager controlled account. These same files
  which control the configuration of the web server, and thus its behavior,
  must also be accessible by the account which runs the web service. If these
  files are altered by a malicious user, the web server would no longer be
  under the control of its managers and owners; properties in the web server
  configuration could be altered to compromise the entire server platform."
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG280"
  tag "gid": "V-2256"
  tag "rid": "SV-6880r1_rule"
  tag "stig_id": "WG280"
  tag "nist": ["AC-3", "Rev_4"]
  
  tag "check": "This check verifies that the SA or Web Manager controlled
  account owns the key web server files. These same files, which control the
  configuration of the web server, and thus its behavior, must also be
  accessible by the account that runs the web service process.

  If it exists, the following file need to be owned by a privileged account.

  .htaccess .htpasswd nginx.conf and its included configuration files

  Use the command find / -name nginx.conf to find the file.  grep ""include"" on
  the nginx.conf file to identify included configuration files. Change to the
  directories that contain the nginx.conf and included configuration files. Use
  the command ls -l on these files to determine ownership of the file

  -The Web Manager or the SA should own all the system files and directories.
  -The configurable directories can be owned by the WebManager or equivalent
  -user.

  Permissions on these files should be 660 or more restrictive.

  If root or an authorized user does not own the web system files and the
  permission are not correct, this is a finding."
  
  tag "fix": "The site needs to ensure that the owner should be the non-
  privileged web server account or equivalent which runs the web service;
  however, the group permissions represent those of the user accessing the web
  site that must execute the directives in .htacces." 

# START_DESCRIBE V-2256
  # describe file(NGINX_CONF_FILE) do
  #   its('mode') { should cmp <= 600 }
  # end


  access_control_files.each do |file|
    file_path = command("find / -name #{file}").stdout.chomp
    unless file_path.to_s.empty?
      describe.one do
        describe file(file_path) do
          it { should be_owned_by WEB_MANAGER }
          its('mode') { should cmp <= 0660 }
        end
        describe file(file_path) do
          it { should be_owned_by SYS_ADMIN }
          its('mode') { should cmp <= 0660 }
        end
      end
    end
  end


  describe.one do
    describe file(NGINX_CONF_FILE) do
      it { should be_owned_by WEB_MANAGER }
      its('mode') { should cmp <= 0660 }
    end
    describe file(NGINX_CONF_FILE) do
      it { should be_owned_by SYS_ADMIN }
      its('mode') { should cmp <= 0660 }
    end
  end

 

# STOP_DESCRIBE V-2256

end
