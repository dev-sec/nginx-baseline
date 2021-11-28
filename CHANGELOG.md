# Changelog

## [2.5.0](https://github.com/dev-sec/nginx-baseline/tree/2.5.0) (2021-11-28)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.4.1...2.5.0)

**Implemented enhancements:**

- add support for tls1.3 protocol [\#51](https://github.com/dev-sec/nginx-baseline/pull/51) ([rndmh3ro](https://github.com/rndmh3ro))

**Merged pull requests:**

- update dhparams to 4096 [\#52](https://github.com/dev-sec/nginx-baseline/pull/52) ([rndmh3ro](https://github.com/rndmh3ro))
- fix rubocop error for Rakefile [\#49](https://github.com/dev-sec/nginx-baseline/pull/49) ([schurzi](https://github.com/schurzi))
- add dependency to chef-config for CI [\#48](https://github.com/dev-sec/nginx-baseline/pull/48) ([schurzi](https://github.com/schurzi))
- use version tag for changelog action [\#47](https://github.com/dev-sec/nginx-baseline/pull/47) ([schurzi](https://github.com/schurzi))
- Fix lint [\#46](https://github.com/dev-sec/nginx-baseline/pull/46) ([schurzi](https://github.com/schurzi))
- GitHub action [\#45](https://github.com/dev-sec/nginx-baseline/pull/45) ([rndmh3ro](https://github.com/rndmh3ro))

## [2.4.1](https://github.com/dev-sec/nginx-baseline/tree/2.4.1) (2021-01-18)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.4.0...2.4.1)

**Merged pull requests:**

- softcoded nginx path [\#43](https://github.com/dev-sec/nginx-baseline/pull/43) ([micheelengronne](https://github.com/micheelengronne))

## [2.4.0](https://github.com/dev-sec/nginx-baseline/tree/2.4.0) (2020-11-08)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.3.4...2.4.0)

**Implemented enhancements:**

- add fedora to valid users library [\#42](https://github.com/dev-sec/nginx-baseline/pull/42) ([rndmh3ro](https://github.com/rndmh3ro))

## [2.3.4](https://github.com/dev-sec/nginx-baseline/tree/2.3.4) (2020-07-23)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.3.3...2.3.4)

## [2.3.3](https://github.com/dev-sec/nginx-baseline/tree/2.3.3) (2020-07-13)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.3.2...2.3.3)

**Merged pull requests:**

- Change default: to value: [\#41](https://github.com/dev-sec/nginx-baseline/pull/41) ([enzomignogna](https://github.com/enzomignogna))

## [2.3.2](https://github.com/dev-sec/nginx-baseline/tree/2.3.2) (2020-06-18)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.3.1...2.3.2)

**Merged pull requests:**

- version alignment [\#40](https://github.com/dev-sec/nginx-baseline/pull/40) ([micheelengronne](https://github.com/micheelengronne))

## [2.3.1](https://github.com/dev-sec/nginx-baseline/tree/2.3.1) (2020-06-18)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.3.0...2.3.1)

**Closed issues:**

- Profile fails `inspec json` [\#33](https://github.com/dev-sec/nginx-baseline/issues/33)

**Merged pull requests:**

- github actions release [\#39](https://github.com/dev-sec/nginx-baseline/pull/39) ([micheelengronne](https://github.com/micheelengronne))
- Declare control source as UTF-8 encoding. [\#34](https://github.com/dev-sec/nginx-baseline/pull/34) ([james-stocks](https://github.com/james-stocks))

## [2.3.0](https://github.com/dev-sec/nginx-baseline/tree/2.3.0) (2019-05-15)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.2.0...2.3.0)

**Merged pull requests:**

- Bump version to 2.3.0 and switch to inspec 3 for check [\#32](https://github.com/dev-sec/nginx-baseline/pull/32) ([alexpop](https://github.com/alexpop))
- Templates [\#30](https://github.com/dev-sec/nginx-baseline/pull/30) ([rndmh3ro](https://github.com/rndmh3ro))
- remove test for hardening.conf file [\#28](https://github.com/dev-sec/nginx-baseline/pull/28) ([rndmh3ro](https://github.com/rndmh3ro))
- use parse\_config instead of parse\_config\_file [\#27](https://github.com/dev-sec/nginx-baseline/pull/27) ([rndmh3ro](https://github.com/rndmh3ro))
- Make nginx-14 and nginx-16 disabled by default based on dev-sec/nginx-baseline\#21 [\#26](https://github.com/dev-sec/nginx-baseline/pull/26) ([woneill](https://github.com/woneill))

## [2.2.0](https://github.com/dev-sec/nginx-baseline/tree/2.2.0) (2018-06-26)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.1.0...2.2.0)

**Closed issues:**

- client\_max\_body\_size 1k disallows file uploads [\#13](https://github.com/dev-sec/nginx-baseline/issues/13)

**Merged pull requests:**

- Duplicated control 'nginx-11' [\#24](https://github.com/dev-sec/nginx-baseline/pull/24) ([pbanderas](https://github.com/pbanderas))
- Control label 'nginx-07' is used twice [\#22](https://github.com/dev-sec/nginx-baseline/pull/22) ([woneill](https://github.com/woneill))

## [2.1.0](https://github.com/dev-sec/nginx-baseline/tree/2.1.0) (2017-11-19)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.0.2...2.1.0)

**Merged pull requests:**

- More nginx controls, add attribute client\_max\_body\_size [\#19](https://github.com/dev-sec/nginx-baseline/pull/19) ([atomic111](https://github.com/atomic111))
- use recommended spdx license identifier [\#18](https://github.com/dev-sec/nginx-baseline/pull/18) ([chris-rock](https://github.com/chris-rock))
- Fix deprecation warnings. [\#17](https://github.com/dev-sec/nginx-baseline/pull/17) ([tmclaugh](https://github.com/tmclaugh))

## [2.0.2](https://github.com/dev-sec/nginx-baseline/tree/2.0.2) (2017-05-08)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.0.1...2.0.2)

**Merged pull requests:**

- update metadata [\#16](https://github.com/dev-sec/nginx-baseline/pull/16) ([chris-rock](https://github.com/chris-rock))
- restrict ruby testing to version 2.3.3 and update gemfile [\#15](https://github.com/dev-sec/nginx-baseline/pull/15) ([atomic111](https://github.com/atomic111))

## [2.0.1](https://github.com/dev-sec/nginx-baseline/tree/2.0.1) (2016-12-22)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2.0.0...2.0.1)

**Closed issues:**

- Tests skipped if command nginx not in PATH [\#12](https://github.com/dev-sec/nginx-baseline/issues/12)

**Merged pull requests:**

- readme update, change log & tooling [\#14](https://github.com/dev-sec/nginx-baseline/pull/14) ([chris-rock](https://github.com/chris-rock))
- fix typo [\#11](https://github.com/dev-sec/nginx-baseline/pull/11) ([rndmh3ro](https://github.com/rndmh3ro))

## [2.0.0](https://github.com/dev-sec/nginx-baseline/tree/2.0.0) (2016-05-03)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/1.0.0...2.0.0)

**Merged pull requests:**

- migrate to inspec profile [\#10](https://github.com/dev-sec/nginx-baseline/pull/10) ([atomic111](https://github.com/atomic111))

## [1.0.0](https://github.com/dev-sec/nginx-baseline/tree/1.0.0) (2015-10-15)

[Full Changelog](https://github.com/dev-sec/nginx-baseline/compare/2661c2a3199aa2dd9823f292c15c786a785149ab...1.0.0)



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
