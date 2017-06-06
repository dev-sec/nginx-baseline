title 'V-2242 - A public web server, if hosted on the NIPRNet, must be isolated in an accredited DoD DMZ Extension.'
control 'V-2242' do
  impact 0.5
  title 'A public web server, if hosted on the NIPRNet, must be isolated in an accredited DoD DMZ Extension.'
  desc 'To minimize exposure of private assets to unnecessary risk by attackers, public web servers must be isolated from internal systems.  Public web servers are by nature more vulnerable to attack from publically based sources, such as the public Internet. Once compromised, a public web server might be used as a base for further attack on private resources, unless additional layers of protection are implemented. Public web servers must be located in a DoD DMZ Extension, if hosted on the NIPRNet, with carefully controlled access. Failure to isolate resources in this way increase risk that private assets are exposed to attacks from public sources.'
  tag 'stig', 'V-2242'
  tag severity: 'medium'
  tag checkid: 'C-33625r2_chk'
  tag fixid: 'F-29264r2_fix'
  tag version: 'WA060 A22'
  tag ruleid: 'SV-32932r2_rule'
  tag nist: 'SC-7'
  tag fixtext: 'Logically relocate the public web server to be isolated from internal systems. In addition, ensure the public web server does not have trusted connections with assets outside the confines of the demilitarized zone (DMZ) other than application and/or database servers that are a part of the same system as the web server.'
  tag checktext: ' Interview the SA or web administrator to see where the public web server is logically located in the data center. Review the site’s network diagram to see how the web server is connected to the LAN. Visually check the web server hardware connections to see if it conforms to the site’s network diagram.   An improperly located public web server is a potential threat to the entire network.  If the web server is not isolated in an accredited DoD DMZ Extension, this is a finding.'

# START_DESCRIBE V-2242
# No Check possible
# STOP_DESCRIBE V-2242

end

