title 'V-2255 - The web server’s htpasswd files (if present) must reflect proper ownership and permissions'
control 'V-2255' do
  impact 0.5
  title 'The web server’s htpasswd files (if present) must reflect proper ownership and permissions'
  desc '"In addition to OS restrictions, access rights to files and directories can be set on a web site using the web server software.  That is, in addition to allowing or denying all access rights, a rule can be specified that allows or denies partial access rights.  For example, users can be given read-only access rights to files, to view the information but not change the files. This check verifies that the htpasswd file is only accessible by system administrators or web managers, with the account running the web service having group permissions of read and execute.  htpasswd is a utility used to provide for password access to web sites."'
  tag 'stig', 'V-2255'
  tag severity: 'medium'
  tag checkid: 'C-2672r2_chk'
  tag fixid: 'F-6758r2_fix'
  tag version: 'WG270 A22'
  tag ruleid: 'SV-36478r2_rule'
  tag nist: 'AC-3'
  tag fixtext: 'The SA or Web Manager account should own the htpasswd file and permissions should be set to 550.'
  tag checktext: 'To locate the htpasswd file enter the following command:

Find / -name htpasswd
Permissions should be r-x r - x - - - (550)

If permissions on htpasswd are greater than 550, this is a finding.

Owner should be the SA or Web Manager account, if another account has access to this file, this is a finding.
'

# START_DESCRIBE V-2255
  htpasswd = command('find / -name htpasswd').stdout.chomp
  htpasswd.split.each do |htpwd|
    describe file(htpwd) do
      its('mode') { should cmp <= 0550 }
    end
  end
# STOP_DESCRIBE V-2255

end

