title 'V-2236 - Installation of a compiler on production web server is prohibited.'
control 'V-2236' do
  impact 0.5
  title 'Installation of a compiler on production web server is prohibited.'
  desc 'The presence of a compiler on a production server facilitates the malicious user’s task of creating custom versions of programs and installing Trojan Horses or viruses. For example, the attacker’s code can be uploaded and compiled on the server under attack.'
  tag 'stig', 'V-2236'
  tag severity: 'medium'
  tag checkid: 'C-33638r4_chk'
  tag fixid: 'F-29279r4_fix'
  tag version: 'WG080 A22'
  tag ruleid: 'SV-32956r3_rule'
  tag nist: 'CM-6'
  tag fixtext: 'Remove any compiler found on the production web server, but if the compiler program is needed to patch or upgrade an application suite in a production environment or the compiler is embedded and will break the suite if removed, document the compiler installation with the ISSO/ISSM and ensure that the compiler is restricted to only administrative users.'
  tag checktext: 'Query the SA and the Web Manager to determine if a compiler is present on the server.  If a compiler is present, this is a finding. 

NOTE:  If the web server is part of an application suite and a compiler is needed for installation, patching, and upgrading of the suite or if the compiler is embedded and cant be removed without breaking the suite, document the installation of the compiler with the ISSO/ISSM and verify that the compiler is restricted to administrative users only.  If documented and restricted to administrative users, this is not a finding.
'

# START_DESCRIBE V-2236
# No Check possible
# STOP_DESCRIBE V-2236

end

