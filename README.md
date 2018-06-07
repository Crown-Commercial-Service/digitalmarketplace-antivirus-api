# digitalmarketplace-antivirus-api

[![Build Status](https://travis-ci.org/alphagov/digitalmarketplace-antivirus-api.svg?branch=master)](https://travis-ci.org/alphagov/digitalmarketplace-antivirus-api)
[![Coverage Status](https://coveralls.io/repos/alphagov/digitalmarketplace-antivirus-api/badge.svg?branch=master&service=github)](https://coveralls.io/github/alphagov/digitalmarketplace-antivirus-api?branch=master)
[![Requirements Status](https://requires.io/github/alphagov/digitalmarketplace-antivirus-api/requirements.svg?branch=master)](https://requires.io/github/alphagov/digitalmarketplace-antivirus-api/requirements/?branch=master)

WIP Antivirus API for Digital Marketplace using ClamAV as a backend.

## Setup
Use `make docker-build` and `make docker-push` to build and push images to the digitalmarketplace org on Docker Hub. Run this image locally, with a port mapped to 80 inside the container in order to make HTTP requests the `/scan` endpoint.
