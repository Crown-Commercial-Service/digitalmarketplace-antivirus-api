# Base builds are defined in https://github.com/Crown-Commercial-Service/ccs-digitalmarketplace-aws-docker-base
FROM digitalmarketplace/dmp-wsgi-antivirus:1.0.0
FROM 473251818902.dkr.ecr.eu-west-2.amazonaws.com/dmp-base-wsgi-antivirus:latest as headless
COPY . ${APP_DIR}
