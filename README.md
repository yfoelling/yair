# Yair
- [Introduction](#introduction)
- [Quick Start](#quick-start)
- [Usage](#usage)

# Introduction
Yair is an lightweight command-line-tool to interact with [Clair](https://github.com/coreos/clair).
It is designed for the execution inside a CI Job, for example to determinate if a Image can be deployed to the production environment.

It can also executed localy without much effort.

features:
  - easy to use
  - fast scans
  - scan public and private images
  - image security scoring - if an Image has to many fixable vulnerabilities, yair will exit with rc 1
  - fancy outputs:
    - table output
    - json output
    - quiet mode (only return code)

# Quick Start
clone repo:
```
git clone git@github.com:yfoelling/yair.git
```
install requirements:
```
pip install -r requirements.txt
```
and you are ready to go!


# Usage
```
Usage: yair.py [options] image:tag

Options:
  -h, --help            show this help message and exit
  -r REGISTRY, --registry=REGISTRY
                        docker registry URL without http/https prefix
  -c CLAIR, --clair=CLAIR
                        clair URL with port
  -o OUTPUT, --output=OUTPUT
                        output format "json", "table" or "quiet"
  -q, --quiet           quiet mode - only exitcode and stderr (-o quiet does
                        the same)
```
if you dont specify a tag, it will assume you want to scan latest
Yair will have an return code of 1, if the vulnerability score is above 379 or it has one with severity "high" or above.

# Preview
This is a previe of a scan. Normaly images will have much more vulnerabilies, so you will get a bigger table.
"Version with fix" will be empty if the vulnerability is not fixed yet for the distributions.
```
./yair.py --clair=MY_CLAIR_SERVER:PORT --registry=OUR_PRIVATE_REGISTRY IMAGE:TAG
╒════════╤════════════╤════════════════╤═════════════════════╤══════════════════════════════════════════════════════════════════╤════════════════════╕
│ Tool   │ Severity   │ CVE name       │ Installed Version   │ Description                                                      │ Version with fix   │
╞════════╪════════════╪════════════════╪═════════════════════╪══════════════════════════════════════════════════════════════════╪════════════════════╡
│ wget   │ High       │ RHSA-2017:3075 │ 1.14-15.el7         │ https://access.redhat.com/errata/RHSA-2017:3075                  │ 1.14-15.el7_4.1    │
│        │            │                │                     │                                                                  │                    │
│        │            │                │                     │ The wget packages provide the GNU Wget file retrieval utility    │                    │
│        │            │                │                     │ for HTTP, HTTPS, and FTP protocols. Security Fix(es): * A stack- │                    │
│        │            │                │                     │ based and a heap-based buffer overflow flaws were found in wget  │                    │
│        │            │                │                     │ when processing chunked encoded HTTP responses. By tricking an   │                    │
│        │            │                │                     │ unsuspecting user into connecting to a malicious HTTP server, an │                    │
│        │            │                │                     │ attacker could exploit these flaws to potentially execute        │                    │
│        │            │                │                     │ arbitrary code. (CVE-2017-13089, CVE-2017-13090) Red Hat would   │                    │
│        │            │                │                     │ like to thank the GNU Wget project for reporting these issues.   │                    │
╘════════╧════════════╧════════════════╧═════════════════════╧══════════════════════════════════════════════════════════════════╧════════════════════╛

the image "IMAGE:TAG" has an vulnerability score of 256
```
This scan had an return code of 1.
