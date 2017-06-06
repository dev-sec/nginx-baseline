title 'V-2247 - Administrators must be the only users allowed access to the directory tree, the shell, or other operating system functions and utilities.'
control 'V-2247' do
  impact 1.0
  title 'Administrators must be the only users allowed access to the directory tree, the shell, or other operating system functions and utilities.'
  desc 'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. This is in addition to the anonymous web user account. The resources to which these accounts have access must also be closely monitored and controlled. Only the SA needs access to all the system’s capabilities, while the web administrator and associated staff require access and control of the web content and web server configuration files. The anonymous web user account must not have access to system resources as that account could then control the server.'
  tag 'stig', 'V-2247'
  tag severity: 'high'
  tag checkid: 'C-29918r3_chk'
  tag fixid: 'F-26806r2_fix'
  tag version: 'WG200 A22'
  tag ruleid: 'SV-36456r2_rule'
  tag nist: 'AC-6'
  tag fixtext: 'Ensure non-administrators are not allowed access to the directory tree, the shell, or other operating system functions and utilities.'
  tag checktext: 'Obtain a list of the user accounts for the system, noting the priviledges for each account.  

Verify with the system administrator or the ISSO that all privileged accounts are mission essential and documented.

Verify with the system administrator or the ISSO that all non-administrator access to shell scripts and operating system functions are mission essential and documented.

If undocumented privileged accounts are found, this is a finding.

If undocumented access to shell scripts or operating system functions is found, this is a finding.'

# START_DESCRIBE V-2247
# No Check possible
# STOP_DESCRIBE V-2247

end

