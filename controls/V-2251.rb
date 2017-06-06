title 'V-2251 - All utility programs, not necessary for operations, must be removed or disabled. '
control 'V-2251' do
  impact 0.1
  title 'All utility programs, not necessary for operations, must be removed or disabled. '
  desc 'Just as running unneeded services and protocols is a danger to the web server at the lower levels of the OSI model, running unneeded utilities and programs is also a danger at the application layer of the OSI model. Office suites, development tools, and graphical editors are examples of such programs that are troublesome. Individual productivity tools have no legitimate place or use on an enterprise, production web server and they are also prone to their own security risks.  '
  tag 'stig', 'V-2251'
  tag severity: 'low'
  tag checkid: 'C-33637r2_chk'
  tag fixid: 'F-29278r1_fix'
  tag version: 'WG130 A22'
  tag ruleid: 'SV-32955r2_rule'
  tag nist: 'CM-6'
  tag fixtext: 'Remove any unnecessary applications.'
  tag checktext: 'If the site requires the use of a particular piece of software, the ISSO will need to maintain documentation identifying this software as necessary for operations. The software must be operated at the vendor’s current patch level and must be a supported vendor release.
If programs or utilities that meet the above criteria are installed on the Web Server, and appropriate documentation and signatures are in evidence, this is not a finding. 

Determine whether the web server is configured with unnecessary software. 

Determine whether processes other than those that support the web server are loaded and/or run on the web server. 

Examples of software that should not be on the web server are all web development tools, office suites (unless the web server is a private web development server), compilers, and other utilities that are not part of the web server suite or the basic operating system. 

Check the directory structure of the server and ensure that additional, unintended, or unneeded applications are not loaded on the system. 

If, after review of the application on the system, there is no justification for the identified software, this is a finding. 
'

# START_DESCRIBE V-2251
# No Check possible
# STOP_DESCRIBE V-2251

end

