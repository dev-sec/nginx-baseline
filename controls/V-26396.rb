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
  description: 'Path for the nginx configuration file',
  default: "/etc/nginx/nginx.conf"
)

control "V-26396" do
  title "HTTP request methods must be limited."

  desc "The HTTP 1.1 protocol supports several request methods which are
  rarely used and potentially high risk. "

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "WA00565 "
  tag "gid": "V-26396"
  tag "rid": "SV-33236r1_rule"
  tag "stig_id": "WA00565 A22"
  tag "nist": ["SC-3", "Rev_4"]

  tag "check": "Review the nginx.conf file and any separate included
  configuration files.

  For every location (except root), ensure the following entry exists:

  ## Only GET, Post, PUT are allowed##
       if ($request_method !~ ^(GET|PUT|POST)$ ) {
           return 444;
       }
  ## In this case, it does not accept other HTTP methods such as HEAD,
  DELETE, SEARCH, TRACE ##

  If the entry is not found for every location, this is a finding."

  tag "fix": "Review the nginx.conf file and any separate included
  configuration files.

  For every location (except root), edit to add the following entry:

  ## Only GET, Post, PUT are allowed##
       if ($request_method !~ ^(GET|PUT|POST)$ ) {
           return 444;
       }
  ## In this case, it does not accept other HTTP methods such as HEAD, DELETE,
  SEARCH, TRACE ##
"

  # START_DESCRIBE V-26396

  if !nginx_conf(NGINX_CONF_FILE).http.nil?
    nginx_conf(NGINX_CONF_FILE).http.each do |http|
      if !http['server'].nil?
        http['server'].each do |server|
          describe server['if'] do
            it { should_not be_nil}
          end
          if !server['if'].nil?
            server['if'].each do |ifcondition|
              describe ifcondition['_'].join do
                it { should cmp '($request_method!~^(GET|PUT|POST)$)'}
              end
              describe ifcondition['return'].join do
                it { should cmp '444'}
              end
            end
          end
        end
      end
    end
  end

  # STOP_DESCRIBE V-26396

end
