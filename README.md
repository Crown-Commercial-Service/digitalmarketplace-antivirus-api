# digitalmarketplace-antivirus-api

[![Build Status](https://travis-ci.org/alphagov/digitalmarketplace-antivirus-api.svg?branch=master)](https://travis-ci.org/alphagov/digitalmarketplace-antivirus-api)
[![Coverage Status](https://coveralls.io/repos/alphagov/digitalmarketplace-antivirus-api/badge.svg?branch=master&service=github)](https://coveralls.io/github/alphagov/digitalmarketplace-antivirus-api?branch=master)
[![Requirements Status](https://requires.io/github/alphagov/digitalmarketplace-antivirus-api/requirements.svg?branch=master)](https://requires.io/github/alphagov/digitalmarketplace-antivirus-api/requirements/?branch=master)
![Python 3.6](https://img.shields.io/badge/python-3.6-blue.svg)

App to scan files in S3 buckets for viruses on demand.

- Python app, based on the [Flask framework](http://flask.pocoo.org/)

## Quickstart

Install [ClamAV](https://www.clamav.net/), specifically its `clamd` tool. This is generally available in most package
repositories.

Install [Virtualenv](https://virtualenv.pypa.io/en/latest/)
```
sudo easy_install virtualenv
```

### Install/Upgrade dependencies

Install Python dependencies with pip

```
make requirements-dev
```

### Run the tests

```
make test
```

### Run the development server

To run the antivirus api for local development you can use the convenient run
script, which sets the required environment variables for local development:
```
make run-app
```

More generally, the command to start the server is:
```
DM_ENVIRONMENT=development flask run
```

### Using the antivirus API locally

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

When using the development server the antivirus API listens on port 5008 by default.
This can be changed by setting the `DM_ANTIVIRUS_API_PORT` environment
variable, e.g. to set the antivirus API port number to 9008:

```
export DM_ANTIVIRUS_API_PORT=9008
```

### Updating application dependencies

`requirements.txt` file is generated from the `requirements-app.txt` in order to pin
versions of all nested dependecies. If `requirements-app.txt` has been changed (or
we want to update the unpinned nested dependencies) `requirements.txt` should be
regenerated with

```
make freeze-requirements
```

`requirements.txt` should be committed alongside `requirements-app.txt` changes.

## Licence

Unless stated otherwise, the codebase is released under [the MIT License][mit].
This covers both the codebase and any sample code in the documentation.

The documentation is [&copy; Crown copyright][copyright] and available under the terms
of the [Open Government 3.0][ogl] licence.

[mit]: LICENCE
[copyright]: http://www.nationalarchives.gov.uk/information-management/re-using-public-sector-information/uk-government-licensing-framework/crown-copyright/
[ogl]: http://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/
