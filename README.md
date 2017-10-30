# Yair
- [Introduction](#introduction)
- [Usage](#usage)
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

## Usage
```
Usage: docker run yfoelling/yair [options] image:tag

Options:
  -h, --help            show this help message and exit
  -r REGISTRY, --registry=REGISTRY
                        docker registry URL without http/https prefix
  -c CLAIR, --clair=CLAIR
                        clair URL with port
  -o OUTPUT, --output=OUTPUT
                        output format "json", "table" or "short-table"
  -q, --quiet           quiet mode - only exitcode
```
if you dont specify a tag, it will assume you want to scan latest.
Yair will have an return code of 1, if the vulnerability score is above 379 or it has one with severity "high" or above.

## Preview
This is a previe of a scan. Normaly images will have much more vulnerabilies, so you will get a bigger table.
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
This scan had an return code of 2.

## Return codes
If the scan exits with return code 2, then the scanned image has either:
- an vulnerability with severity "high" or higher\
**or** 
- a score above 379

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

