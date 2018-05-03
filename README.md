# Yair
#### **[Available on Dockerhub](https://hub.docker.com/r/yfoelling/yair/)** 

## Table of contents:
- [Introduction](#introduction)
- [Getting started](#getting-started)
- [Preview](#preview)
- [Return codes](#return-codes)
- [Image scoring](#image-scoring)

## Introduction
Yair is an lightweight command-line-tool to interact with [Clair](https://github.com/coreos/clair).
It is designed for the execution inside a CI Job, for example to determinate if an image can be deployed to the production environment.

It can also executed localy without much effort.

features:
  - easy to use
  - fast scans
  - scan public and private images
  - image security scoring - if an image has to many fixable vulnerabilities, yair will have an return code of 2
  - multiple output option:
    - table output
    - short table
    - json output
    - quiet mode
    - Rocket.Chat output

## Getting started
#### Configuration:
copy the "config.yaml.tmpl" of this repo an change it for your needs.
```yaml
---
registry:
  host: "registry.hub.docker.com"

clair:
  host: "localhost:6060"

output:
  format: table
  rocketchat:
    webhook_url: rocket-chat.com/hooks/...
    receiver: "#general,@admin"

fail_on:
  score: 379
  big_vulnerability: true
```
| Config Option | Description |
|---|---|
| registry::host | hostname of the Docker Registry, can be overwritten with "--registry" Argument |
| clair::host | hostname of the Clair Server with Port |
| output::format | specifys the output format, can be "json", "table", "short-table" or "quiet" | 
| output::rocketchat | Rocket.Chat ouput, leave config commented if you dont want to use it |
| output::rocketchat::webhook_url | url to the Rocket.Chat hook you configured for this output with http/https prefix |
| output::rocketchat::receiver | comma-seperated list of channels to send output to |
| fail_on::score | if the image vulerability score is above this value, th script will have an returncode of "2" |
| fail_on::big_vulnerability | if set to true, the script will have an returncode of "2", if the image has an vulnerability with severity "high" or higher |

Rename the customized "config.yaml.tmpl" to "config.yaml" and move it to the directory you want to execute it in. 
#### Usage:
The config.yaml will be made accessable for yair with a readonly docker volume:
``` 
docker run -v `pwd`:/opt/yair/config/:ro yfoelling/yair [registry]image[tag]
```
you can also change the source path to a fixed path where you config.yaml is located.

You can scan public images and private images. if you dont specify a tag, it will assume you want to scan latest.
```
docker run yfoelling/yair ubuntu
docker run yfoelling/yair mynamespace/myimage:mytag
```

## Preview
#### "table"
This is a preview of a scan with output::format "table". Normaly images will have much more vulnerabilies, so you will get a bigger table.
"Version with fix" will be empty if the vulnerability is not fixed yet for the distributions.
```
+---------------------+----------------+------------------------------------------------------------------+--------------------+
| Package             | CVE Name       | CVE Link                                                         | Version with fix   |
| Installed Version   | Severity       | CVE Description                                                  |                    |
+=====================+================+==================================================================+====================+
| wget                | RHSA-2017:3075 | https://access.redhat.com/errata/RHSA-2017:3075                  | 1.14-15.el7_4.1    |
|                     |                |                                                                  |                    |
| 1.14-15.el7         | High           | The wget packages provide the GNU Wget file retrieval utility    |                    |
|                     |                | for HTTP, HTTPS, and FTP protocols. Security Fix(es): * A stack- |                    |
|                     |                | based and a heap-based buffer overflow flaws were found in wget  |                    |
|                     |                | when processing chunked encoded HTTP responses. By tricking an   |                    |
|                     |                | unsuspecting user into connecting to a malicious HTTP server, an |                    |
|                     |                | attacker could exploit these flaws to potentially execute        |                    |
|                     |                | arbitrary code. (CVE-2017-13089, CVE-2017-13090) Red Hat would   |                    |
|                     |                | like to thank the GNU Wget project for reporting these issues.   |                    |
+---------------------+----------------+------------------------------------------------------------------+--------------------+
scan result for: IMAGE_NAME
the image has "high" vulnerabilities
```

#### "short-table"
This is a preview of a scan with output::format "short-table".
"Version with fix" will be empty if the vulnerability is not fixed yet for the distributions.
```
$ docker run -v `pwd`:/opt/yair/config/:ro yfoelling/yair:latest  ubuntu
+------------+----------------+------------+--------------------+
| Package    | CVE Name       | Severity   | Version with fix   |
|------------+----------------+------------+--------------------|
| systemd    | CVE-2017-15908 | Medium     |                    |
| db5.3      | CVE-2017-10140 | Medium     |                    |
| apparmor   | CVE-2016-1585  | Medium     |                    |
| glibc      | CVE-2017-8804  | Medium     |                    |
| glibc      | CVE-2017-12132 | Medium     |                    |
| perl       | CVE-2016-1238  | Medium     |                    |
| perl       | CVE-2017-12883 | Medium     |                    |
| perl       | CVE-2017-12837 | Medium     |                    |
| util-linux | CVE-2016-5011  | Low        |                    |
| util-linux | CVE-2016-2779  | Low        |                    |
| glibc      | CVE-2015-8985  | Low        |                    |
| glibc      | CVE-2015-5180  | Low        |                    |
| perl       | CVE-2017-6512  | Low        |                    |
| shadow     | CVE-2013-4235  | Low        |                    |
| shadow     | CVE-2017-12424 | Low        |                    |
| pcre3      | CVE-2017-6004  | Low        |                    |
| pcre3      | CVE-2017-7244  | Low        |                    |
| pcre3      | CVE-2017-7186  | Low        |                    |
| coreutils  | CVE-2016-2781  | Low        |                    |
| cryptsetup | CVE-2016-4484  | Low        |                    |
| bzip2      | CVE-2016-3189  | Low        |                    |
| ncurses    | CVE-2017-13730 | Negligible |                    |
| ncurses    | CVE-2017-13731 | Negligible |                    |
| ncurses    | CVE-2017-13733 | Negligible |                    |
| ncurses    | CVE-2017-13732 | Negligible |                    |
| ncurses    | CVE-2017-10684 | Negligible |                    |
| ncurses    | CVE-2017-13728 | Negligible |                    |
| ncurses    | CVE-2017-11112 | Negligible |                    |
| ncurses    | CVE-2017-11113 | Negligible |                    |
| ncurses    | CVE-2017-13729 | Negligible |                    |
| ncurses    | CVE-2017-13734 | Negligible |                    |
| ncurses    | CVE-2017-10685 | Negligible |                    |
| glibc      | CVE-2016-10228 | Negligible |                    |
| pcre3      | CVE-2017-7246  | Negligible |                    |
| pcre3      | CVE-2017-7245  | Negligible |                    |
| dpkg       | CVE-2017-8283  | Negligible |                    |
+------------+----------------+------------+--------------------+
scan result for: library/ubuntu:latest
```


## Return codes
If the scan exits with return code 2, then the scanned image has either:
- an vulnerability with severity "high" or higher
**OR** 
- a score above 379

you can configure these thresholds in the config.yaml "fail_on" section.

## Image scoring
If an vulnerability is detected and there is already a version of the affected package with a fix, then a number will be added to the score depending on the severity:

| Severity | Score |
|---|---|
| Unknown | 0 |
| Negligible | 1 |
| Low | 16 |
| Medium | 81 |
| High | 265 |
| Critical | 625 |
| Defcon1 | 1296 |

