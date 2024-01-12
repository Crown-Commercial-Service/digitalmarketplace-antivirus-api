# Base builds are defined in https://github.com/Crown-Commercial-Service/ccs-digitalmarketplace-aws-docker-base
FROM 473251818902.dkr.ecr.eu-west-2.amazonaws.com/dmp-base-wsgi-antivirus:latest
# Should not be required
# COPY --chown=uwsgi:uwsgi . ${APP_DIR}
