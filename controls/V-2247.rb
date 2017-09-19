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

SYS_ADMIN = attribute(
  'sys_admin',
  description: "The system adminstrator",
  default: 'root'
)

NGINX_OWNER = attribute(
  'nginx_owner',
  description: "The Nginx owner",
  default: 'nginx'
)

only_if do
  command('nginx').exist?
end

control "V-2247" do

  title "Administrators must be the only users allowed access to the directory
  tree, the shell, or other operating system functions and utilities."

  desc "As a rule, accounts on a web server are to be kept to a minimum. Only
  administrators, web managers, developers, auditors, and web authors require
  accounts on the machine hosting the web server. This is in addition to the
  anonymous web user account. The resources to which these accounts have
  access must also be closely monitored and controlled. Only the SA needs
  access to all the system’s capabilities, while the web administrator and
  associated staff require access and control of the web content and web
  server configuration files. The anonymous web user account must not have
  access to system resources as that account could then control the server."

  impact 0.7
  tag "severity": "high"
  tag "gtitle": "WG200"
  tag "gid": "V-2247"
  tag "rid": "SV-36456r2_rule"
  tag "stig_id": "WG200 A22"
  tag "nist": ["AC-6", "Rev_4"]

  tag "check": "Obtain a list of the user accounts for the system, noting the
  priviledges for each account.

  Verify with the system administrator or the ISSO that all privileged accounts
  are mission essential and documented.

  Verify with the system administrator or the ISSO that all non-administrator
  access to shell scripts and operating system functions are mission essential
  and documented.

  If undocumented privileged accounts are found, this is a finding.

  If undocumented access to shell scripts or operating system functions is
  found, this is a finding."

  tag "fix": "Ensure non-administrators are not allowed access to the
  directory tree, the shell, or other operating system functions and
  utilities."



  begin
    users.shells(/bash/).usernames.each do |account|
      describe account do
        it { should match %r(#{SYS_ADMIN}|#{NGINX_OWNER}) }
      end
    end

    if users.shells(/bash/).usernames.empty?
      describe do
        skip "Skipped: no users found with shell acccess."
      end
    end
  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
