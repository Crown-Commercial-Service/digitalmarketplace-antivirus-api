FROM digitalmarketplace/base-api:3.1.1

ENV CLAMAV_VERSION 0.

RUN echo "deb http://http.debian.net/debian/ stretch main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://http.debian.net/debian/ stretch-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://security.debian.org/ stretch/updates main contrib non-free" >> /etc/apt/sources.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        build-essential \
        clamav-daemon=${CLAMAV_VERSION}* \
        clamav-freshclam=${CLAMAV_VERSION}* \
        libclamunrar7 \
        wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN wget -O /var/lib/clamav/main.cvd http://database.clamav.net/main.cvd && \
    wget -O /var/lib/clamav/daily.cvd http://database.clamav.net/daily.cvd && \
    wget -O /var/lib/clamav/bytecode.cvd http://database.clamav.net/bytecode.cvd && \
    chown clamav:clamav /var/lib/clamav/*.cvd

RUN mkdir /var/run/clamav && \
    chown clamav:clamav /var/run/clamav && \
    chmod 750 /var/run/clamav

RUN sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/clamd.conf && \
    echo "TCPSocket 3310" >> /etc/clamav/clamd.conf

RUN usermod -a -G clamav www-data

COPY config/freshclam.conf /etc/clamav

COPY config/additional-supervisord.conf /home/vcap/additional-supervisord.conf
RUN cat /home/vcap/additional-supervisord.conf >> /etc/supervisord.conf

COPY config/additional-awslogs.conf /home/vcap/additional-awslogs.conf
RUN cat /home/vcap/additional-awslogs.conf >> /etc/awslogs.conf

COPY scripts/inject-sns-ips-into-nginx-api-conf.py /usr/local/sbin/inject-sns-ips-into-nginx-api-conf.py
COPY templates/api.j2 /etc/nginx/templates/api.j2
COPY config/logrotate.conf /etc/logrotate.d/amazon_ip_update
RUN echo "@reboot . /app/venv/bin/activate && /usr/local/sbin/inject-sns-ips-into-nginx-api-conf.py" | crontab -
RUN (crontab -l && echo "*/5 * * * * . /app/venv/bin/activate && /usr/local/sbin/inject-sns-ips-into-nginx-api-conf.py") | crontab -
