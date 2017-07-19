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

control "V-2234" do

  title "Public web server resources must not be shared with private assets."

  desc "It is important to segregate public web server resources from private
  resources located behind the DoD DMZ in order to protect private assets.
  When folders, drives or other resources are directly shared between the
  public web server and private servers the intent of data and resource
  segregation can be compromised.

  In addition to the requirements of the DoD Internet-NIPRNet DMZ STIG that
  isolates inbound traffic from the external network to the internal network,
  resources such as printers, files, and folders/directories will not be shared
  between public web servers and assets located within the internal network.
  "

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG040"
  tag "gid": "V-2234"
  tag "rid": "SV-32957r1_rule"
  tag "stig_id": "WG040 A22"
  tag "nist": ["SC-7", "Rev_4"]

  tag "check": "Determine whether the public web server has a two-way trusted
  relationship with any private asset located within the network. Private web
  server resources (e.g., drives, folders, printers, etc.) will not be
  directly mapped to or shared with public web servers.

  If sharing is selected for any web folder, this is a finding.

  The following checks indicate inappropriate sharing of private resources with
  the public web server:

  If private resources (e.g., drives, partitions, folders/directories, printers,
  etc.) are shared with the public web server, then this is a finding. "
  
  tag "fix": "Configure the public web server to not have a trusted
  relationship with any system resource that is also not accessible to the
  public. Web content is not to be shared via Microsoft shares or NFS mounts."

end
