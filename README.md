# pe-source #

[![GitHub Build Status](https://github.com/cisagov/pe-source/workflows/build/badge.svg)](https://github.com/cisagov/pe-source/actions)
[![CodeQL](https://github.com/cisagov/pe-source/workflows/CodeQL/badge.svg)](https://github.com/cisagov/pe-source/actions/workflows/codeql-analysis.yml)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/pe-source/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/pe-source?branch=develop)
[![Known Vulnerabilities](https://snyk.io/test/github/cisagov/pe-source/develop/badge.svg)](https://snyk.io/test/github/cisagov/pe-source)

This package is used to gather and store data for the CISA Posture & Exposure Reports
[P&E Reports](https://github.com/cisagov/pe-reports).

Data of interest include *Exposed Credentials, Domain Masquerading, Malware,
Inferred Vulnerabilities and the Dark Web*. The data collected for the reports
is gathered on the 1st and 15th of each month.

## Requirements ##

- [Python Environment](CONTRIBUTING.md#creating-the-python-virtual-environment)

## Installation ##

- `git clone https://github.com/cisagov/pe-source.git`

- Add database/API credentials to `src/pe_source/data/pe_db/database.ini`

- `pip install -e .`

## Run P&E Source ##

```console
Usage:
    pe-source DATA_SOURCE [--log-level=LEVEL] [--orgs=ORG_LIST] [--cybersix-methods=METHODS] [--soc_med_included]

Arguments:
  DATA_SOURCE                       Source to collect data from. Valid values are "cybersixgill",
                                    "dnstwist", "hibp", "intelx", and "shodan".

Options:
  -h --help                         Show this message.
  -v --version                      Show version information.
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
  -o --orgs=ORG_LIST                A comma-separated list of orgs to collect data for.
                                    If not specified, data will be collected for all
                                    orgs in the pe database. Orgs in the list must match the
                                    IDs in the cyhy-db. E.g. DHS,DHS_ICE,DOC
                                    [default: all]
  -csg --cybersix-methods=METHODS   A comma-separated list of cybersixgill methods to run.
                                    If not specified, all will run. Valid values are "alerts",
                                    "credentials", "mentions", "topCVEs". E.g. alerts,mentions.
                                    [default: all]

```

## Examples ##

Run shodan on DHS and DOT:

```console
pe-source shodan --orgs=DHS,DOT
```

Run Cybersixgill mentions on DHS and include social media data:

```console
pe-source cybersixgill --cybersix-methods=mentions --orgs=DHS --soc_med_included
```

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
