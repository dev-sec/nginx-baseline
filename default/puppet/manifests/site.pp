
class { 'nginx': }

class { 'nginx_hardening':
  provider => 'jfryman/nginx'
}
