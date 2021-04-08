# Digital Marketplace Antivirus API
![Python 3.6](https://img.shields.io/badge/python-3.6-blue.svg)

API application for Digital Marketplace.

- Python app, based on the [Flask framework](http://flask.pocoo.org/)

This app scan files in S3 buckets for viruses on demand.

## Quickstart

Install [ClamAV](https://www.clamav.net/), specifically its `clamd` tool. This is generally available in most package
repositories.

You can then clone the repo and run:

```
make run-all
```

This command will install dependencies and start the app.

By default, the app will be served at [http://127.0.0.1:5008](http://127.0.0.1:5008).

### Using the Antivirus API locally

Start `clamd` if not already running (in a new console window/tab):

```bash
clamd
```

The antivirus API expects to connect to `clamd` over a unix socket. The location of this unix socket can be set by the
configuration variable `DM_CLAMD_UNIX_SOCKET_PATH`. The default may be fine if you're running a system `clamd` or the
docker image.

Calls to the antivirus API require a valid bearer
token. For development environments, this defaults to `myToken`. An example request to your local antivirus API
would therefore be:

```
curl -i -H "Authorization: Bearer myToken" 127.0.0.1:5008/end/point
```

## Testing

Run the full test suite:

```
make test
```

To only run the Python tests:

```
make test-unit
```

To run the `flake8` linter:

```
make test-flake8
```

### Updating Python dependencies

`requirements.txt` file is generated from the `requirements.in` in order to pin
versions of all nested dependencies. If `requirements.in` has been changed (or
we want to update the unpinned nested dependencies) `requirements.txt` should be
regenerated with

```
make freeze-requirements
```

`requirements.txt` should be committed alongside `requirements.in` changes.

## Contributing

This repository is maintained by the Digital Marketplace team at the [Government Digital Service](https://github.com/alphagov).

If you have a suggestion for improvement, please raise an issue on this repo.

### Reporting Vulnerabilities

If you have discovered a security vulnerability in this code, we appreciate your help in disclosing it to us in a
responsible manner.

Please follow the [GDS vulnerability reporting steps](https://github.com/alphagov/.github/blob/master/SECURITY.md),
giving details of any issue you find. Appropriate credit will be given to those reporting confirmed issues.

## Licence

Unless stated otherwise, the codebase is released under [the MIT License][mit].
This covers both the codebase and any sample code in the documentation.

The documentation is [&copy; Crown copyright][copyright] and available under the terms
of the [Open Government 3.0][ogl] licence.

[mit]: LICENCE
[copyright]: http://www.nationalarchives.gov.uk/information-management/re-using-public-sector-information/uk-government-licensing-framework/crown-copyright/
[ogl]: http://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/
