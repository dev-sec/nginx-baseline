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

control "V-2242" do

  title "A public web server, if hosted on the NIPRNet, must be isolated in an
  accredited DoD DMZ Extension."
  
  desc "To minimize exposure of private assets to unnecessary risk by
  attackers, public web servers must be isolated from internal systems.Public
  web servers are by nature more vulnerable to attack from publically based
  sources, such as the public Internet. Once compromised, a public web server
  might be used as a base for further attack on private resources, unless
  additional layers of protection are implemented. Public web servers must be
  located in a DoD DMZ Extension, if hosted on the NIPRNet, with carefully
  controlled access. Failure to isolate resources in this way increase risk
  that private assets are exposed to attacks from public sources."
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA060"
  tag "gid": "V-2242"
  tag "rid": "SV-32932r2_rule"
  tag "stig_id": "WA060 A22"
  tag "nist": ["SC-7", "Rev_4"]
  
  tag "check": "Interview the SA or web administrator to see where the public
  web server is logically located in the data center. Review the site’s
  network diagram to see how the web server is connected to the LAN. Visually
  check the web server hardware connections to see if it conforms to the
  site’s network diagram. An improperly located public web server is a
  potential threat to the entire network.If the web server is not isolated in
  an accredited DoD DMZ Extension, this is a finding."
  
  tag "fix": "Logically relocate the public web server to be isolated from
  internal systems. In addition, ensure the public web server does not have
  trusted connections with assets outside the confines of the demilitarized
  zone (DMZ) other than application and/or database servers that are a part of
  the same system as the web server."

end
