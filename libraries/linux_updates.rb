# encoding: utf-8
# copyright: 2016, Christoph Hartmann
# copyright: 2016, Dominik Richter
# license: MPLv2
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

require 'json'

class LinuxUpdateManager < Inspec.resource(1)
  name 'linux_update'
  desc 'Use the linux_update InSpec audit resource to test for available or installed updates'

  def initialize
    if inspec.os.redhat?
      @update_mgmt = RHELUpdateFetcher.new(inspec)
    elsif inspec.os.debian?
      @update_mgmt = UbuntuUpdateFetcher.new(inspec)
    end
    return skip_resource 'The `linux_update` resource is not supported on your OS.' if @update_mgmt.nil?
  end

  def updates
    return [] if @update_mgmt.nil?
    u = @update_mgmt.updates
    return [] if u.nil? || u.empty?
    u['available']
  end

  def uptodate?
    return nil if @update_mgmt.nil?
    u = @update_mgmt.updates
    return false if u.nil? || !u['available'].empty?
    true
  end

  def packages
    return [] if @update_mgmt.nil?
    p = @update_mgmt.packages
    return [] if p.nil? || u.empty?
    p['installed']
  end

  def to_s
    'Linux Update'
  end
end

class UpdateFetcher
  def initialize(inspec)
    @inspec = inspec
  end

  def packages
    []
  end

  def updates
    []
  end

  def parse_json(script)
    cmd = @inspec.bash(script)
    begin
      JSON.parse(cmd.stdout)
    rescue JSON::ParserError => _e
      return []
    end
  end
end

class UbuntuUpdateFetcher < UpdateFetcher
  def packages
    ubuntu_packages = ubuntu_base + <<-EOH
echo -n '{"installed":['
dpkg-query -W -f='${Status}\\t${Package}\\t${Version}\\t${Architecture}\\n' |\\
  grep '^install ok installed\\s' |\\
  awk '{ printf "{\\"name\\":\\""$4"\\",\\"version\\":\\""$5"\\",\\"arch\\":\\""$6"\\"}," }' | rev | cut -c 2- | rev | tr -d '\\n'
echo -n ']}'
EOH
    parse_json(ubuntu_packages)
  end

  def updates
    ubuntu_updates = ubuntu_base + <<-EOH
echo -n '{"available":['
DEBIAN_FRONTEND=noninteractive apt-get upgrade --dry-run | grep Inst | tr -d '[]()' |\\
  awk '{ printf "{\\"name\\":\\""$2"\\",\\"version\\":\\""$4"\\",\\"repo\\":\\""$5"\\",\\"arch\\":\\""$6"\\"}," }' | rev | cut -c 2- | rev | tr -d '\\n'
echo -n ']}'
EOH
    parse_json(ubuntu_updates)
  end

  private

  def ubuntu_base
    base = <<-EOH
  #!/bin/sh
  DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1
  readlock() { cat /proc/locks | awk '{print $5}' | grep -v ^0 | xargs -I {1} find /proc/{1}/fd -maxdepth 1 -exec readlink {} \\; | grep '^/var/lib/dpkg/lock$'; }
  while test -n "$(readlock)"; do sleep 1; done
  echo " "
    EOH
    base
  end
end

class RHELUpdateFetcher < UpdateFetcher
  def packages
    rhel_packages = <<-EOH
sleep 2 && echo " "
echo -n '{"installed":['
rpm -qa --queryformat '"name":"%{NAME}","version":"%{VERSION}-%{RELEASE}","arch":"%{ARCH}"\\n' |\\
  awk '{ printf "{"$1"}," }' | rev | cut -c 2- | rev | tr -d '\\n'
echo -n ']}'
EOH
    parse_json(rhel_packages)
  end

  def updates
    rhel_updates = <<-EOH
#!/bin/sh
python -c 'import sys; sys.path.insert(0, "/usr/share/yum-cli"); import cli; list = cli.YumBaseCli().returnPkgLists(["updates"]);res = ["{\\"name\\":\\""+x.name+"\\", \\"version\\":\\""+x.version+"-"+x.release+"\\",\\"arch\\":\\""+x.arch+"\\",\\"repository\\":\\""+x.repo.id+"\\"}" for x in list.updates]; print "{\\"available\\":["+",".join(res)+"]}"'
EOH
    puts rhel_updates
    cmd = @inspec.bash(rhel_updates)
    unless cmd.exit_status == 0
      # essentially we want https://github.com/chef/inspec/issues/1205
      STDERR.puts 'Could not determine patch status.'
      return nil
    end

    first = cmd.stdout.index('{')
    res = cmd.stdout.slice(first, cmd.stdout.size - first)
    begin
      JSON.parse(res)
    rescue JSON::ParserError => _e
      return []
    end
  end
end
