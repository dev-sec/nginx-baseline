
class { 'nginx':
  package_source => 'system'
}

class { 'nginx_hardening::jfryman':
  package_source => 'system'
}
