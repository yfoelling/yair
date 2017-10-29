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
  - fast Scans
  - scan public and private images
  - image security scoring - if an Image has to many vulnerabilities, yair will exit with rc 1
  - fancy outputs:
    - table output
    - json output
    - quiet mode (only RC)

# Quick Start

clone repo:
```git clone git@github.com:yfoelling/yair.git
```
install requiremnts:
```pip install -r requirements.txt
```
and you are ready to go!


# Usage
```Usage: yair.py [options] image:tag

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

