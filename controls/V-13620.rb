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

control "V-13620" do

  title "A private web server’s list of CAs in a trust hierarchy must lead to
  an authorizedDoD PKI Root CA."

  desc "A PKI certificate is a digital identifier that establishes the identity
  of an individual or a platform. A server that has a certificate provides
  users with third-party confirmation of authenticity. Most web browsers
  perform server authentication automatically and the user is notified only if
  the authentication fails. The authentication process between the server and
  the client is performed using the SSL/TLS protocol. Digital certificates are
  authenticated, issued, and managed by a trusted Certificate Authority (CA).

  The use of a trusted certificate validation hierarchy is crucial to the
  ability to control access to a site’s server and to prevent unauthorized
  access. Only DoD-approved PKIs will be utilized. "

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WG355"
  tag "gid": "V-13620"
  tag "rid": "SV-32936r1_rule"
  tag "stig_id": "WG355 A22"
  tag "nist": ["IA-5", "SC-12", "Rev_4"]

  tag "check": "Enter the following command:

  find / -name ssl.conf  note the path of the file.

  grep ""SSLCACertificateFile"" /path/of/ssl.conf

  Review the results to determine the path of the SSLCACertificateFile.

  more /path/of/ca-bundle.crt

  Examine the contents of this file to determine if the trusted CAs are DoD
  approved. If the trusted CA that is used to authenticate users to the web site
  does not lead to an approved DoD CA, this is a finding.

  NOTE: There are non DoD roots that must be on the server in order for it to
  function. Some applications, such as anti-virus programs, require root CAs to
  function. DoD approved certificate can include the External Certificate
  Authorities (ECA), if approved by the DAA. The PKE InstallRoot 3.06 System
  Administrator Guide (SAG), dated 8 Jul 2008, contains a complete list of DoD,
  ECA, and IECA CAs."

  tag "fix": "Configure the web server’s trust store to trust only DoD-
  approved PKIs (e.g., DoD PKI, DoD ECA, and DoD-approved external partners)."

  describe x509_certificate(SSL_CERT) do
  end
  end

end
