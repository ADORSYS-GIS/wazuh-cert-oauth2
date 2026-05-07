# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

[72d28d6](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/72d28d6dc2db34be3ca733f75d146709e10eeddb)...[b7b5999](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b7b59990d7cb75d9f6fb9f0e9172aaae33f2f072)

### Bug Fixes

- Correct OS check in install script ([`fb03a89`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/fb03a89f97aa1cd65a6219745326f785d973d1ff))

### Documentation

- Update CHANGELOG.md and checksums [skip ci] ([`8b1735f`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/8b1735f3e031dc68c210e0d41cffeabceaab6f4f))
- Update CHANGELOG.md and checksums [skip ci] ([`0c7afcf`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/0c7afcf65fb278abcdf0c24a2932660998d67328))
- Update CHANGELOG.md and checksums [skip ci] ([`b7b5999`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b7b59990d7cb75d9f6fb9f0e9172aaae33f2f072))

## 0.4.2-rc.1 - 2026-04-01

[fb5e8e7](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/fb5e8e747d8bff8092ab6b36cd9ecef128cba212)...[72d28d6](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/72d28d6dc2db34be3ca733f75d146709e10eeddb)

### Documentation

- Update CHANGELOG.md and checksums [skip ci] ([`9eb6070`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9eb6070143ff63f728ffd63789807aa74a6c2f89))

### Features

- Add step to generate and include binary and script checksums in release workflow ([`8ad9ee0`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/8ad9ee04ee6d2f7364a2ead238caee221eac0c01))

### Miscellaneous Tasks

- Remove script checksums from release pull request description ([`117bceb`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/117bcebd4cb17f72a0dcec5cdb76d78e62f8ab19))
- Include checksums.sha256 in release workflow updates and pull requests ([`72d28d6`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/72d28d6dc2db34be3ca733f75d146709e10eeddb))

## 0.4.2-rc.2 - 2026-04-15

[606f48c](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/606f48cbcc95995008f77c0094fb8391b7904f6b)...[fb5e8e7](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/fb5e8e747d8bff8092ab6b36cd9ecef128cba212)

### Bug Fixes

- Corrected checksums for binaries ([`39265f2`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/39265f2cef8a82a0522a084c1aa4b6fc566c1101))
- Corrected aarch64 darwin checksum ([`05ce12e`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/05ce12e959fdd1733835bd48a8ad013c6b7f9303))
- Corrected utils.ps1 bootstrap verification ([`b66602d`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b66602d2897b2e993de0bfebcf0365095d269ccb))
- Corrected cert-oauth2 repository references ([`80efcb6`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/80efcb6184b5ba7bc1326788b613250100d6868a))
- Corrected sed function name in all scripts ([`9e589c2`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9e589c28f33ba7c65225d86573ab5ac48a49d0b9))
- Updated url to checksum file for client binary in install scripts and add error message for absent checksums ([`b8708a9`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b8708a9cddb9cd59ffd59cd55d5ddd0b63610310))
- Use $IsWindows for OS detection instead of PSEdition ([`161d41b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/161d41baed4bb781c1ccdc9ff3dba7b1f8433fe6))
- Corrected binary checksum url in install.ps1 ([`a55dc6b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/a55dc6b75ee5f3f20252945a2ed7b09d0a6c2190))

### Features

- Added shared folder with common utilities ([`9c5d38b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9c5d38b754c7fc8e6f4402c6c849cd14fe7b7ba7))
- Feat(ci): add path constraints to linting ci ([`cd01f87`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cd01f87dd0a98df95313671579a2c153f361073d))

### Miscellaneous Tasks

- Update CHANGELOG.md ([`1b6a86c`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1b6a86c6773c2caa83ec54e1e4dc402361ce8cf1))
- Add checksums.sha256 file for script integrity verification ([`1e17ef4`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1e17ef4e298d8ed9fcc3fb97aba7c21e8bfd50ee))
- Added workflow to lint and test scripts ([`df5a1da`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/df5a1da9b2feb7bd347bc7755b1e17e4d8c093cf))
- Update checksums.sha256 ([`716955e`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/716955e7d7aa642476f2827e7ae7e2adb2f21508))
- Update checksums.sha256 ([`ba84f78`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/ba84f78d9446496941c3db6fbb50eb62fc6453f2))
- Update checksums.sha256 ([`9258c7c`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9258c7c0af72d9ea5719163b3c40ee8d98bc2032))
- Update checksums.sha256 ([`68153c1`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/68153c1f1360dd8ca53f6e6c32fbb29e76400963))
- Update GitHub workflow for changelog and checksum automation ([`fb5e8e7`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/fb5e8e747d8bff8092ab6b36cd9ecef128cba212))

### Refactor

- Split installation and uninstallation scripts for Linux and macOS ([`d8e5c2c`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/d8e5c2c86cb43dd0ad7a73e44b628932a80706d4))
- Use printf for ANSI color codes in common.sh ([`c71eeeb`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/c71eeebc10d654e7d81f1a5353b624f484cf0518))
- Change shebang from /bin/sh to /bin/bash in install and uninstall scripts; update color definitions in common.sh ([`b9750cc`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b9750cc76107db463b501413e102c997590a3780))
- Change logging function to use printf for better formatting in common.sh ([`01b9f71`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/01b9f71156f61ec5b8158a81379fadae407e8059))
- Replace echo with printf in log function for improved formatting ([`bfc0357`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/bfc035733fd4cc24ec09e7ed6007d2faabc9af1f))
- Update ANSI color definitions to use $'...' syntax for better compatibility; fix log function formatting ([`61301d9`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/61301d97f5ec6d137e0e1a380c95601d3cb7357b))
- Enhance logging functions and ANSI color definitions in install script ([`f9d41fc`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/f9d41fc2130be1f8d40c03d08005ea760addc227))
- Remove inline logging functions and ANSI color definitions; source common script instead ([`dc27fd2`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/dc27fd292c22c090db665ee12565c21367c09c22))
- Change shebang from /bin/sh to /bin/bash for improved script compatibility ([`4d10f00`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4d10f0050e16cf27f40e8c411d48efcfa8744270))
- Enhance logging functions and remove dependency on common script ([`ca45036`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/ca4503648ee8840f07d7a33a4337cbb00a400059))
- Consolidate logging functions and remove common script dependencies in install/uninstall scripts ([`4677584`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/467758465cd2be887ebe54a7c1afa43f97c092a8))
- Add OS checks in install/uninstall scripts for Linux and MacOS compatibility ([`c2f858f`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/c2f858fd3ff5914fbebcfbdea3774a6a68f6ae57))
- Use parameter expansion for OSSEC_CONF_PATH and BIN_DIR in install/uninstall scripts ([`613b0ce`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/613b0ce113afc35d1bc6a278da1c9cffc5d1f11f))
- Update OS checks and logging in installation and uninstallation scripts for Linux and macOS ([`f91365f`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/f91365f838f3c845f83559cc00aa10625368deaa))

## 0.4.2 - 2026-02-27

[5f8ce9a](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/5f8ce9a4c27153ef037f643bab5060010c7a832b)...[606f48c](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/606f48cbcc95995008f77c0094fb8391b7904f6b)

### Miscellaneous Tasks

- Added release notes and changelog generation ([`606f48c`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/606f48cbcc95995008f77c0094fb8391b7904f6b))

## wazuh-cert-webhook-0.4.2 - 2026-02-23

[1e5ef4b](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1e5ef4bfaf25e800e20e237e04d93cd9340a7f0a)...[5f8ce9a](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/5f8ce9a4c27153ef037f643bab5060010c7a832b)

### Features

- Add installation validation function to install.ps1 ([`a4ccf29`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/a4ccf2999400a95a577a5d064b43a61a667d4c2a))

### Miscellaneous Tasks

- Update default WOPS version to 0.4.0 in install.ps1 ([`949eb56`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/949eb56ab5c3339cc1b4f8a443f38061a3a258b7))

## 0.4.1 - 2026-02-20

[19d4bdd](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/19d4bddd2b2d28097794ac3efd58db3451d8c5f1)...[1e5ef4b](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1e5ef4bfaf25e800e20e237e04d93cd9340a7f0a)

### Bug Fixes

- Handle browser launch correctly under sudo ([`90bddc1`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/90bddc127a58ce9bba36311b3a6a05fd5791e8b8))
- Launch browser as desktop user with proper GUI env ([`569c3d3`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/569c3d3464669247164faa53fea5549cd375a6ba))
- Handle browser launch correctly under sudo (#130) ([`1e5ef4b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1e5ef4bfaf25e800e20e237e04d93cd9340a7f0a))

### Miscellaneous Tasks

- Upgrade WOPS_VERSION -> 0.4.1 ([`ce69977`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/ce69977cea80ec1abe3fdecd052a2da8ef563955))
- Upgrade app version -> 0.4.2 ([`a32bee6`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/a32bee60f4e30120fcaa4f4d6b2e12f35b29440f))

## wazuh-cert-webhook-0.4.0 - 2025-11-27

[efb8a61](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/efb8a6134ca5f700dc5d3df15b39d9f011eda9a0)...[19d4bdd](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/19d4bddd2b2d28097794ac3efd58db3451d8c5f1)

## 0.4.0 - 2025-11-27

[7a40e71](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/7a40e716057f9b3310b24bce4a9d642347f0840c)...[efb8a61](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/efb8a6134ca5f700dc5d3df15b39d9f011eda9a0)

### Bug Fixes

- Update open_in_browser function for Windows to use rundll32 to avoid parsing issues ([`43cee46`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/43cee462a83721eb59765dac0ffa5e7d514105b9))

### Miscellaneous Tasks

- Upgrade WOPS_VERSION -> 0.4.0 ([`efb8a61`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/efb8a6134ca5f700dc5d3df15b39d9f011eda9a0))

## wazuh-cert-webhook-0.3.0 - 2025-11-16

[fc05634](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/fc05634eda78b6126dcb1864d69d6731bc266b2d)...[7a40e71](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/7a40e716057f9b3310b24bce4a9d642347f0840c)

### Miscellaneous Tasks

- Version upgrade => 0.3.0 ([`7a40e71`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/7a40e716057f9b3310b24bce4a9d642347f0840c))

## 0.2.23-rc.5 - 2025-11-16

[5131ce2](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/5131ce260b8463198eeee77f8ece82ba9df7c0bb)...[fc05634](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/fc05634eda78b6126dcb1864d69d6731bc266b2d)

### Miscellaneous Tasks

- Version upgrade ([`fc05634`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/fc05634eda78b6126dcb1864d69d6731bc266b2d))

## 0.2.23-rc.4 - 2025-11-16

[6ab2efd](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/6ab2efd1b9e0e67787e0ab14922a4f4b11221993)...[5131ce2](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/5131ce260b8463198eeee77f8ece82ba9df7c0bb)

### Bug Fixes

- Cert gen ([`5131ce2`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/5131ce260b8463198eeee77f8ece82ba9df7c0bb))

## 0.2.23-rc.3 - 2025-11-15

[74062f7](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/74062f7e3622e2671d5568ced6f2b41aa6f2a6c3)...[6ab2efd](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/6ab2efd1b9e0e67787e0ab14922a4f4b11221993)

### Miscellaneous Tasks

- Dockerfile uograded to use musl ([`b9c2374`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b9c237486a38930dba78812fad926637d2623c40))
- Dockerfile multi-arch support ([`bc258ae`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/bc258ae4b8284948b155cd639223003cbd524c22))
- Port config ([`4cc0013`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4cc0013086b9ee0281ac21234ba6d484fb64c70c))
- Version upgrade ([`1561121`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/15611217bf46bcd226aed3ec3d36403f30e5d975))
- Format ([`49c4382`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/49c4382eb0a33767a84d6fbae654921cc10fbae0))
- Format ([`6ab2efd`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/6ab2efd1b9e0e67787e0ab14922a4f4b11221993))

## 0.2.23-rc.2 - 2025-11-15

[1bcce7b](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1bcce7b3158113b0a74d5d8637bf72cc519d0f21)...[74062f7](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/74062f7e3622e2671d5568ced6f2b41aa6f2a6c3)

### Miscellaneous Tasks

- Openssl vendored ([`63244e9`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/63244e98018af0195d7e688095eaed90b3c033a4))
- Openssl vendored ([`98a353e`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/98a353e0203212f46d6bf244822af033595f86e8))
- Openssl vendored ([`13e99f0`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/13e99f053f561c4b67938b9a060d889a70364331))
- Openssl vendored ([`02bb220`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/02bb220caf9a640dbb6a7ddfab650dbb8b7f61f5))
- Openssl vendored ([`3d6ce38`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/3d6ce388a329f9f03667fb41b5841446359291fa))
- Openssl vendored ([`eba2a09`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/eba2a099a903dcf7046a20b25db3b1999c95cdf0))
- Openssl vendored ([`d5ead56`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/d5ead5670a3a3bd4fdd13eeff19977adbd9c89ad))
- Openssl vendored ([`0527ff0`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/0527ff0c3040ae68f363dd46742b1be050e49758))
- Openssl vendored ([`319c7ca`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/319c7ca31a2a33a2d216b303d0edf772b0c49382))
- Openssl vendored ([`25a12e8`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/25a12e861eebeb1b5da1190d539252bb0712157c))
- Openssl vendored ([`4053a63`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4053a63eb7a60e3dfee4f60bf892187c03a57622))
- Openssl vendored ([`3d11f7d`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/3d11f7d8c07160409e591dcbbe8239cceef68986))
- Openssl vendored ([`915b415`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/915b415ee269569d774ece15d98d01306a8f4124))
- Openssl vendored ([`ffd1aeb`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/ffd1aeb6e882a5e7866df9f700538256610605d3))
- Openssl vendored ([`c8fb05b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/c8fb05bed50a81a13b0791c54e505d150dd7f7fb))
- Openssl vendored ([`145b3d1`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/145b3d10a1df5a92bbfd53fa3c8cdab9f6213d45))
- Version upgrade ([`74062f7`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/74062f7e3622e2671d5568ced6f2b41aa6f2a6c3))

## 0.2.23-rc.1 - 2025-11-13

[0027b43](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/0027b431802240ba77b1e5afb02c731f817c1486)...[1bcce7b](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1bcce7b3158113b0a74d5d8637bf72cc519d0f21)

### Miscellaneous Tasks

- Version upgrade ([`1bcce7b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1bcce7b3158113b0a74d5d8637bf72cc519d0f21))

## wazuh-cert-webhook-0.2.27 - 2025-11-13

[96d33d9](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/96d33d9e56b4b07f9e0b982fd642507e0cbbf1b9)...[0027b43](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/0027b431802240ba77b1e5afb02c731f817c1486)

### Miscellaneous Tasks

- Version upgrade ([`0027b43`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/0027b431802240ba77b1e5afb02c731f817c1486))

## wazuh-cert-webhook-0.2.26 - 2025-11-13

[a90ee1c](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/a90ee1c358816e8fb11ea26b3895caebc21d4c83)...[96d33d9](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/96d33d9e56b4b07f9e0b982fd642507e0cbbf1b9)

### Miscellaneous Tasks

- Version upgrade ([`96d33d9`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/96d33d9e56b4b07f9e0b982fd642507e0cbbf1b9))

## wazuh-cert-server-0.2.25 - 2025-11-13

[b9a5b31](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b9a5b311421a5053d5d77e51363575447b10174f)...[a90ee1c](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/a90ee1c358816e8fb11ea26b3895caebc21d4c83)

### Miscellaneous Tasks

- Version upgrade ([`a90ee1c`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/a90ee1c358816e8fb11ea26b3895caebc21d4c83))

## wazuh-cert-webhook-0.2.25 - 2025-11-13

[750a0d3](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/750a0d3e87d524db040eb844c7e3bcd132c8ecd5)...[b9a5b31](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b9a5b311421a5053d5d77e51363575447b10174f)

### Miscellaneous Tasks

- Version upgrade ([`b9a5b31`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b9a5b311421a5053d5d77e51363575447b10174f))

## wazuh-cert-webhook-0.2.24 - 2025-11-13

[cda4ad5](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cda4ad514597986371059347db43b66b36477a06)...[750a0d3](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/750a0d3e87d524db040eb844c7e3bcd132c8ecd5)

### Miscellaneous Tasks

- Version upgrade ([`750a0d3`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/750a0d3e87d524db040eb844c7e3bcd132c8ecd5))

## wazuh-cert-server-0.2.24 - 2025-11-13

[9c83dd5](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9c83dd547471cd8d5c442db6c2228b10f6d377ee)...[cda4ad5](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cda4ad514597986371059347db43b66b36477a06)

### Miscellaneous Tasks

- Version upgrade ([`cda4ad5`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cda4ad514597986371059347db43b66b36477a06))

## wazuh-cert-webhook-0.2.23 - 2025-11-13

[9cbeef5](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9cbeef5a4e70912b973887bc23ad988f7efbd7a2)...[9c83dd5](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9c83dd547471cd8d5c442db6c2228b10f6d377ee)

### Miscellaneous Tasks

- Version upgrade ([`9c83dd5`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9c83dd547471cd8d5c442db6c2228b10f6d377ee))

## wazuh-cert-webhook-0.2.22 - 2025-11-13

[09e5872](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/09e5872556a4c8adec750eecdcca640036da9f69)...[9cbeef5](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9cbeef5a4e70912b973887bc23ad988f7efbd7a2)

### Miscellaneous Tasks

- Version upgrade ([`9cbeef5`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9cbeef5a4e70912b973887bc23ad988f7efbd7a2))

## wazuh-cert-server-0.2.22 - 2025-11-13

[909f44f](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/909f44f02d94f1c3c0926846a3f2a2826be60706)...[09e5872](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/09e5872556a4c8adec750eecdcca640036da9f69)

### Features

- Jwt prefered username (#81) ([`09e5872`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/09e5872556a4c8adec750eecdcca640036da9f69)), Co-authored-by:t-desmond <desmondtardzenyuy@gmail.com>

## 0.2.22-rc.1 - 2025-10-07

[375eda5](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/375eda5352719d331b66ab45d9f5572059dfe1ee)...[909f44f](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/909f44f02d94f1c3c0926846a3f2a2826be60706)

### Bug Fixes

- Remove icacls executable does not need to be assigned exe permissions ([`1405c10`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1405c10bb16903321738b43bd35c66f86bfb2422))
- Add executable permissions to cert-oauth2.exe for windows of all languages ([`084599c`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/084599cc00832d791eeca98d061e6ffb4f547103))

## wazuh-cert-webhook-0.2.21 - 2025-09-08

[b5f3e73](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b5f3e7321ebb5bcef95726ffba0e9dbaf6fe30db)...[375eda5](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/375eda5352719d331b66ab45d9f5572059dfe1ee)

### Miscellaneous Tasks

- Csv s3 backup ([`09b636b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/09b636b316bf2f2df4e45caa220e851c0cb5f9e5))
- Version upgrade ([`14e2117`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/14e2117101ef082f978d740a38c33384edce2547))
- Version upgrade ([`375eda5`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/375eda5352719d331b66ab45d9f5572059dfe1ee))

## 0.2.20-rc.3 - 2025-09-08

[68ee741](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/68ee7413febfb81fdeecac1242824107c510f5f7)...[b5f3e73](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b5f3e7321ebb5bcef95726ffba0e9dbaf6fe30db)

### Bug Fixes

- Build.yml removed manual sbom ([`b5f3e73`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b5f3e7321ebb5bcef95726ffba0e9dbaf6fe30db))

### Miscellaneous Tasks

- Version upgrade (#33) ([`2033863`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/20338636f5a50d530e9fdb09eb101ed6269c4061))
- Removed optional sbom from build ci (#34) ([`1c1ef00`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1c1ef005b1789bdd4ee47d0b1f1768b69a5e01b6))

## wazuh-cert-webhook-0.2.20 - 2025-09-07

[397e412](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/397e4120cf847885be48459c7a69c6162732c742)...[67484c5](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/67484c5e2370de047078f2ce42a4e28bb1e27c94)

### Features

- CRL helm charts and Upgrade Code structure (#23) ([`67484c5`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/67484c5e2370de047078f2ce42a4e28bb1e27c94))

## 0.2.19 - 2025-06-04

[e62144a](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/e62144a2da80234768ffc130d093c7a2d56c2702)...[397e412](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/397e4120cf847885be48459c7a69c6162732c742)

### Miscellaneous Tasks

- Release version 0.2.18 ([`397e412`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/397e4120cf847885be48459c7a69c6162732c742))

## 0.2.18 - 2025-05-26

[2523b0e](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2523b0ed7b47d209565c370074bb9b34aecea892)...[e62144a](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/e62144a2da80234768ffc130d093c7a2d56c2702)

### Bug Fixes

- Add restart_agent and stop_agent services to fix set_name issue on windows ([`b2a4f30`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b2a4f30329fbfa77b894fb199370be23045c4db2))
- Update wazuh-cert-oauth2-client version to 0.2.18 and remove unused restart_agent import ([`cd52bee`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cd52bee6baeeb01303f197369877818fea14bb4d))
- Update wazuh-cert-oauth2-client version to 0.2.18 and remove unused restart_agent import ([`539d4b0`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/539d4b08d9e0016ff77afeed70193ffe97101c2b))
- Update restart_agent and stop_agent to use powershell commands for Windows ([`ac14caf`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/ac14caf10bd8de808997a13d4cd92d38f2575cd9))
- Add success message after agent enrollment completion ([`f8c7179`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/f8c7179f75bf180678a3bbbf513474b578c8c788))
- Update default WOPS version to 0.2.18 in install scripts ([`192a150`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/192a150debd3321aacf77e33d2140980bb5c4f94))
- Add logging for agent name update confirmation ([`6107eba`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/6107ebaedc285655c24c7ab65c37418f342a6bd8))

## 0.2.17 - 2025-02-19

[f9bda04](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/f9bda049563b96e4f0633789a50f2a3e6102ee03)...[2523b0e](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2523b0ed7b47d209565c370074bb9b34aecea892)

### Bug Fixes

- Remove update agent_name functionality ([`b17db81`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b17db81e0360a68116eb1d82a820ff79dce9aa29))
- Add agentName as placeholder in enrollment block ([`5e9147a`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/5e9147a85eddad365f88e838a636de5ed86a76eb))
- Set omit xml declaration to true ([`c9d9004`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/c9d9004045eb1676434a7b04bda507e2d90fbd42))
- Change Logging Method to match other scripts ([`0fca750`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/0fca75006e6c6c9545039c9613ea8fbd9591a5d2))
- Bin url and removed unecessary variables ([`f2ca906`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/f2ca9069bcc5554e7b16932f54081da004d36830))
- Bin url ([`b8f7691`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b8f7691c258a791a29e44a0b2739b15b240d0435))

### Miscellaneous Tasks

- Add placeholder agent name ([`cbc4521`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cbc4521efd40d04fac2a63d674e5c60bc0e159c1))

## 0.2.16 - 2025-02-11

[033e8fc](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/033e8fc7e2b350fbbd46cffb7bea762d75a1b667)...[f9bda04](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/f9bda049563b96e4f0633789a50f2a3e6102ee03)

### Miscellaneous Tasks

- Version upgrade -> 0.2.16 ([`e233767`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/e2337673b4243607756a32351bc4ce86f36f3847))
- Better CI ([`f9bda04`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/f9bda049563b96e4f0633789a50f2a3e6102ee03))

## 0.2.15 - 2025-02-11

[6d4a155](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/6d4a155286520a4d80390c438b90b675cfaf9857)...[033e8fc](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/033e8fc7e2b350fbbd46cffb7bea762d75a1b667)

### Bug Fixes

- Enrollment block is not added in correct position ([`8faab5a`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/8faab5a6c23bd0ba8a026f5b930de636bdea878b))

### Features

- Optimized docker file (#8) ([`8248ee8`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/8248ee8f7360560e51d2b5815ed5722520374138))

### Miscellaneous Tasks

- Add enrollment block after server block ([`62759af`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/62759af011bc8062d4e2d4dde8ff29483b765f3e))
- Version upgrade ([`033e8fc`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/033e8fc7e2b350fbbd46cffb7bea762d75a1b667))

## 0.2.13 - 2025-01-17

[8afeadf](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/8afeadffeceb441c5552da6dc14445937996b5f6)...[6d4a155](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/6d4a155286520a4d80390c438b90b675cfaf9857)

### Bug Fixes

- Use gsed to rename agent in macos ([`1f08ebf`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1f08ebff8c67c85a2309d7e2b96e1253555d12b7))

### Miscellaneous Tasks

- WOPS_VERSION -> 0.2.13 ([`c87d670`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/c87d670c155ad8048a2e1a592a9c2c13e5d029a3))
- Client-version -> 0.2.13 ([`6d4a155`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/6d4a155286520a4d80390c438b90b675cfaf9857))

### Testing

- Update env variables ([`96ee04a`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/96ee04a4ca6598cf9d5b0f29c2a64fd0cf0e56e4))

### Debug

- Add debugging line in set_name function ([`5d18e2a`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/5d18e2a5df4318bc07db4c5ffe0fe88d81ecd7e7))

## 0.2.12 - 2025-01-17

[85eb7f0](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/85eb7f05a810fd09e26ef8a4151395592e83e1c8)...[8afeadf](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/8afeadffeceb441c5552da6dc14445937996b5f6)

### Bug Fixes

- Add maybe_sudo infront of file checks ([`00d12d6`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/00d12d68dcf781f4f586c6afe23daa432a24afd2))
- Add maybe_sudo infront of file checks ([`6b3491b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/6b3491b9e2f0ddd462482b00c6582ccde9445092))
- Add maybe_sudo where needed and add sed_alternative in uninstall script ([`59fe944`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/59fe944ad9ab0ed33d932d80024c65e1470dfd15))
- Add sed_alternative in uninstall script ([`83f8d45`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/83f8d45ae757cd457d636c76815a5c52b91c92c2))
- Remove maybe_sudo where needed ([`360b4c0`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/360b4c08b80451d9a62c4d125e23504a5be2b56d))
- Remove maybe_sudo where needed ([`c33edaf`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/c33edaf728df7f6e3129d9a070edb3f5ddd3eebb))
- Error handling if binary already exists. File is replaced by new installation ([`3f91176`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/3f9117619ae1c6f0f1e905b20c93f4fb6aaa4766))
- Simplify and improve certificate configuration ([`2c7e0d8`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2c7e0d815cd52d731e1e171b0ad5c79489ede898))
- Update windows path to ossec.conf to not be in etc folder ([`cfa2d1b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cfa2d1b8d7258f508a2388c7f201cba9fa93d2f0))
- Syntax error line 32 expected ; but found path_buf ([`180bfad`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/180bfad243d4d3eb17c87f05ed43ee0eec9b3795))
- Remove whitespace between cfg! and ( on line 27 ([`0cca62a`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/0cca62a7abd086652f7280d7650843e6a3d6b6ea))
- Remove semi-colon from line 30 and line 28 & some syntax formatting ([`dd62b61`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/dd62b617c34ae284e2d680437b504ae9215dfa89))
- Agent_name is added in 1 line rather than 2 lines ([`4430b66`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4430b66b897eb8cac19392c8e8d9bb5111a19516))
- Using powershell as command instead of sed ([`8afeadf`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/8afeadffeceb441c5552da6dc14445937996b5f6))

### Enhance

- Added colours to message printing function ([`73b0de2`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/73b0de2328e1cb2bb3542bb491e4b28587f94494))

### Features

- Add uninstall script ([`5b258f7`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/5b258f775dd138c2a5cbd3f2bc826518914d7411))
- Add installation validation steps ([`153eeed`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/153eeeddf4911643a30b64f1aa1ca901a5a2d26f))
- Update sed command to work for windows os ([`fb65a5e`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/fb65a5ed2f34c1b9552665e882a732c36e810d06))
- Add functionality to sed edit agent_name for windows ([`2b84c08`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2b84c08c6d0eb077decb1243fd99434820b4d96a))

### Miscellaneous Tasks

- Update default WOPS_VERSION to 0.2.11 ([`1e6f769`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1e6f7693c7a403dbc4a737c3b1a512c1ee5fa71e))
- DEFAULT_WOPS_VERSION -> 0.2.12 ([`2a38f78`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2a38f78c0018fbddcc078338d8833acf7c7d7843))
- Correct ossec config path ([`b186c53`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/b186c53ffae726cbe349ad6a418840d938a4f40c))

## 0.2.11 - 2024-12-17

[29d33d0](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/29d33d0b213f8b9adc6decf21a0b105159f78052)...[85eb7f0](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/85eb7f05a810fd09e26ef8a4151395592e83e1c8)

### Features

- Version upgrade ([`85eb7f0`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/85eb7f05a810fd09e26ef8a4151395592e83e1c8))

## 0.2.10 - 2024-12-17

[25b3e72](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/25b3e72f43bf99b1dc42a061f0c00dd6abd0d911)...[29d33d0](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/29d33d0b213f8b9adc6decf21a0b105159f78052)

### Bug Fixes

- Use different sed command depending on OS ([`366aa3d`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/366aa3d7ad4abcd8258b21efce0f467c4a6fa53f))

### Features

- Fix sed -> sed_alternative ([`29d33d0`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/29d33d0b213f8b9adc6decf21a0b105159f78052))

## 0.2.9 - 2024-12-03

[2737cde](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2737cde5f0c5f1ae30cb129bc7ccc5ffda4f5c50)...[25b3e72](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/25b3e72f43bf99b1dc42a061f0c00dd6abd0d911)

### Features

- Fix name with special char ([`25b3e72`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/25b3e72f43bf99b1dc42a061f0c00dd6abd0d911))

## 0.2.8 - 2024-10-22

[e37849e](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/e37849e10ee933d0f6c427de06370f5037948fd7)...[2737cde](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2737cde5f0c5f1ae30cb129bc7ccc5ffda4f5c50)

### Features

- Windows installation path ([`866c18b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/866c18b9580097b189b2be95322e81260ebe4534))
- Windows path for certs ([`2737cde`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2737cde5f0c5f1ae30cb129bc7ccc5ffda4f5c50))

### Miscellaneous Tasks

- Update ossec conf path to be multiplatform ([`7c9dc13`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/7c9dc13ff273bc8808f99968e7b860b3af2c3870))

## 0.2.6 - 2024-10-11

[c731411](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/c7314117cdc8dd3cbf2956bd8ab572eda7c6312f)...[e37849e](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/e37849e10ee933d0f6c427de06370f5037948fd7)

### Bug Fixes

- Linux deps ([`17c5367`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/17c5367ab3298dffc744f902d559271b028fdfe1))
- Linux deps ([`f4b9a82`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/f4b9a829d1e5bd20247d050cb0d0e2cdcb48efac))
- Linux deps ([`e37849e`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/e37849e10ee933d0f6c427de06370f5037948fd7))

### Documentation

- Added more descriptive comments ([`627081d`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/627081d7ee311b8fb5dd75dc1c1bcdca722af36c))

### Miscellaneous Tasks

- Configure agent certificates in ossec.conf ([`524c576`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/524c576405f8fff35debd9cf3e293fe7d5a62c83))
- Configure agent certificates in ossec.conf ([`3dfbbb4`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/3dfbbb46259365d41dbb3e11f556a2332b6c2387))
- Configure agent certificates in ossec.conf ([`392345c`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/392345cb22ecd2243bdeb8f296b7484ead70c4ce))
- Update WOPS version to 0.2.5 and handle download fallback ([`5b30347`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/5b30347285667a735068560312abcbba2340aad7))
- Efs config; v0.2.5 ([`868b210`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/868b210d035bae7bb44594b9e39ae8cfc7512143))
- Certificates config ([`4fd1b53`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4fd1b53a8d807c6f495b1fe5d4973ff2446c40de))
- Certificates config ([`e842743`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/e842743f22404e813b7697a9e977aa88c18a30bb))
- Updated set_name to use smaller names; version upgrade till 0.2.6; ([`42e7ed1`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/42e7ed1ab9247d47c1cc53de8c363936ca267d80))

## 0.2.4 - 2024-10-04

[75299d2](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/75299d24a6cc6e4c24afd2793867f9597cc302f5)...[c731411](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/c7314117cdc8dd3cbf2956bd8ab572eda7c6312f)

### Miscellaneous Tasks

- Efs config; v0.2.4 ([`16ce0e8`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/16ce0e81206d04d6a19c862d03e7dc3c66e0c5b9))
- Efs config; v0.2.4 ([`c731411`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/c7314117cdc8dd3cbf2956bd8ab572eda7c6312f))

## 0.2.3 - 2024-10-04

[ce5a430](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/ce5a430adbcdf08f9d57f5bf1e6f16df532ac805)...[75299d2](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/75299d24a6cc6e4c24afd2793867f9597cc302f5)

### Miscellaneous Tasks

- Removed unused tests ([`04b8851`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/04b88516a0b3dff3aa97d250299b8a23b77fa2b1))
- Agent_name added; version upgrade to 0.2.3 ([`75299d2`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/75299d24a6cc6e4c24afd2793867f9597cc302f5))

## 0.2.2 - 2024-10-01

[4d0d70e](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4d0d70eaa198b800ead0f1a80c488cf77dcf9e97)...[ce5a430](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/ce5a430adbcdf08f9d57f5bf1e6f16df532ac805)

### Bug Fixes

- Permission in script ([`e7e5d92`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/e7e5d92570de77a3439a5fb71d298cd599b4bcf2))
- Make source shell universal ([`100f3b7`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/100f3b74afb6eea31cd68f9c649b1e38502ebdab))
- Solve sed command call ([`41e786b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/41e786b7b2596488eeaea3d23b1023f1a1ed06a7))

### Miscellaneous Tasks

- Config ([`01fa2da`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/01fa2da7ed1aca18bd6076c492cdea8c594c9ce8))
- Config ([`96d43ea`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/96d43ea8d7a8aa75c1851e12e2ea0d524a7b7c75))
- Improve certs configuration ([`8252866`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/8252866ddd4aec773168307fb1b84f713310303b))
- Used sed_alternative ([`e8a8cb0`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/e8a8cb071ce69df5267a252a9a7588b719f99d16))
- Default values for MacOS; version upgrade to 0.2.2 ([`ce5a430`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/ce5a430adbcdf08f9d57f5bf1e6f16df532ac805))

### Refactor

- Improve script ([`50e223c`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/50e223c6cc9ac36ff46645b6371ade8062a897ee))

### Bump

- Updated version for consistency ([`d08f828`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/d08f82827370173f2beb929a6c23f34a45da93d1))

## 0.2.1 - 2024-09-12

[4872171](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4872171f6505d96f9f18dbcc0c97e2189a4d00ff)...[4d0d70e](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4d0d70eaa198b800ead0f1a80c488cf77dcf9e97)

### Miscellaneous Tasks

- Updated windows script ([`4d0d70e`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4d0d70eaa198b800ead0f1a80c488cf77dcf9e97))

## 0.2.0 - 2024-09-12

[cb80194](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cb80194265434c8bcfd6aac3c6a82cd9b1480092)...[4872171](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4872171f6505d96f9f18dbcc0c97e2189a4d00ff)

### Bug Fixes

- Ci docker non-interactive ([`01cf38e`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/01cf38e71298ebc34bc27d57babc581e5d6d8ff1))

### Features

- Added ossec.conf update ([`6ac0717`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/6ac0717a33c96eca9675e4d192ccfcc144735955))
- Tests written using bats ([`16b5a33`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/16b5a339bc080a7b6460548921a33233512f5260))

### Miscellaneous Tasks

- Typo changes ([`0501e73`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/0501e73d3be4003d0a7344438f7df7ec9234c769))
- More colors to the bash script ([`f97296e`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/f97296eac41dd0fb09789f9387254458f8a7be55))
- Updated keycloak issuer to wazuh's keycloak ([`4872171`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4872171f6505d96f9f18dbcc0c97e2189a4d00ff))

## 0.1.7 - 2024-08-15

[cb6cc5d](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cb6cc5d66f9fe712f1bb63b35de21e986f50bdf3)...[cb80194](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cb80194265434c8bcfd6aac3c6a82cd9b1480092)

### Bug Fixes

- Test-script scripts ([`4ee7cd3`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/4ee7cd3db793ae0cf8a4580d84843429a89c4cc4))
- Added buildx ([`f38861d`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/f38861de8912a4d07493f92fd417882aea45d94e))
- Script date arg ([`a8f6542`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/a8f65421a4c606a5e92372d832e9fcf2c789f636))

### Miscellaneous Tasks

- Added curl to images ([`94f11e3`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/94f11e3979131c0a3981f04012b7b22a6035457d))

### Testing

- Fix script docker test cases ([`83ccdc9`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/83ccdc9f48475606105ae10121e13154bd65dcff))
- Fix script docker test cases ([`cb80194`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cb80194265434c8bcfd6aac3c6a82cd9b1480092))

## 0.1.7 - 2024-08-15

[1cf24cf](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1cf24cf698b151950ca4d985f9109ba580fc6008)...[cb6cc5d](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cb6cc5d66f9fe712f1bb63b35de21e986f50bdf3)

### Miscellaneous Tasks

- V0.1.7 ([`cb6cc5d`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cb6cc5d66f9fe712f1bb63b35de21e986f50bdf3))

## 0.1.6 - 2024-08-15

[66b3e15](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/66b3e15bf5f8e34c79a7b9ccdce990683a4275e4)...[1cf24cf](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1cf24cf698b151950ca4d985f9109ba580fc6008)

### Miscellaneous Tasks

- Helm chart ingress fix ([`d973077`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/d973077ebe576a2f0be90456917b22d138d20e27))
- Helm chart ingress fix ([`d9d5dbc`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/d9d5dbc1fdde5586f9a356fdc4eb382adb7c1ded))
- Helm chart sa fix ([`794455a`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/794455ad1ca47324e082624e8867d466453a848e))
- Helm chart image fix ([`a96fa89`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/a96fa8941c5b665afd01831741020bd075d1ffc5))
- Rocket config address ([`eacfe11`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/eacfe110af665488c0b5833746ac6c0bd2ac7089))
- Rocket re-config address ([`765504b`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/765504b68a65af537ceb7a8c257c8bc18011c9a0))
- Scripts updated for non-interactive bash ([`7d44f4f`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/7d44f4f5702402f1e7974ad4e9d6ad94907f199d))
- Updated README.md ([`fd499d9`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/fd499d9ab727d41e4f22719aa03415373402a8ca))
- Structure changes ([`bdb22f4`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/bdb22f424fdda423b5ebcc162042957a31a62c80))
- V0.1.6 ([`1cf24cf`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/1cf24cf698b151950ca4d985f9109ba580fc6008))

## 0.1.5 - 2024-08-13

[2438d15](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2438d1599d1734c0397526bb25de14c9b35cf633)...[66b3e15](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/66b3e15bf5f8e34c79a7b9ccdce990683a4275e4)

### Bug Fixes

- Openssl ([`66b3e15`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/66b3e15bf5f8e34c79a7b9ccdce990683a4275e4))

### Miscellaneous Tasks

- Helm charts version update ([`cf5beef`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cf5beef75e99dd3c9a3e09c40b98cbd1e6370f1f))
- Update script versions ([`cc61760`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cc617609fc2a0cf85c6eddac8040364b46d94ce8))

## 0.1.4 - 2024-08-13

[2c23933](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2c23933288ca4d275cc9bb0aa8bd4c8546316285)...[2438d15](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2438d1599d1734c0397526bb25de14c9b35cf633)

### Miscellaneous Tasks

- First ready script, tested ([`3c42742`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/3c427429f27444fe505a4cb777edaf9de003cdc5))
- Helm charts ([`2438d15`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2438d1599d1734c0397526bb25de14c9b35cf633))

## 0.1.3 - 2024-08-13

[9538a91](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9538a913d346ff69cac8d1131affaf9666b80561)...[2c23933](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2c23933288ca4d275cc9bb0aa8bd4c8546316285)

### Miscellaneous Tasks

- First ready script, tested ([`2c23933`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/2c23933288ca4d275cc9bb0aa8bd4c8546316285))

## 0.1.2 - 2024-08-13

[5d9a9cd](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/5d9a9cd267b5ac7bbe4d74bc442ef7d1987b7e6e)...[9538a91](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9538a913d346ff69cac8d1131affaf9666b80561)

### Miscellaneous Tasks

- First ready script, tested ([`9538a91`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/9538a913d346ff69cac8d1131affaf9666b80561))

## 0.1.1 - 2024-08-13

### Miscellaneous Tasks

- Initial commit ([`7bf0572`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/7bf05724182772389c56a288fe13de608c9fb99c))
- Setup github action ([`67e5e21`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/67e5e218543684cce52f79478109a21b9c2c3c3a))
- Setup helm chart ([`30aa000`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/30aa0004b6beb77b3bdf7847de53258411b3894d))
- Readme ([`d99d482`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/d99d48284e1035fa2d498481bbdd8a36ffb8e078))
- Project structure ([`46b3c78`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/46b3c780d2761553b469b547ee23b96c6c6281c2))
- Client ([`7507539`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/75075399cd6117270832e9c1eadc3fe431767bc0))
- First ready version ([`cdc7771`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/cdc7771b3c1230bf67902cbcf740b3496f161084))
- First ready script ([`5d9a9cd`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/5d9a9cd267b5ac7bbe4d74bc442ef7d1987b7e6e))

### Typo

- Changed title of workflow ([`0599873`](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/commit/059987304899bb5c95e6ac7005b66f19c14405ba))

<!-- generated by git-cliff -->
