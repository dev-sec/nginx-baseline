DevSec Nginx Baseline
=====================

This Compliance Profile ensures, that all hardening projects keep the same quality.

- https://github.com/dev-sec/ansible-nginx-hardening
- https://github.com/dev-sec/chef-nginx-hardening
- https://github.com/dev-sec/puppet-nginx-hardening

## Standalone Usage

This Compliance Profile requires [InSpec](https://github.com/chef/inspec) for execution:

```
$ git clone https://github.com/dev-sec/nginx-baseline
$ inspec exec nginx-baseline
```

You can also execute the profile directly from Github:

```
$ inspec exec https://github.com/dev-sec/nginx-baseline
```

## License and Author

* Author:: Patrick Muench <patrick.muench1111@googlemail.com>
* Author:: Dominik Richter <dominik.richter@googlemail.com>
* Author:: Christoph Hartmann <chris@lollyrock.com>

* Copyright 2014-2016, The Hardening Framework Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
