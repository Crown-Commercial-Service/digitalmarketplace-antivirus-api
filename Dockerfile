FROM digitalmarketplace/base-api:9.2.0

ENV CLAMAV_VERSION 0.

RUN echo "deb http://http.debian.net/debian/ buster main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://http.debian.net/debian/ buster-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://security.debian.org/ buster/updates main contrib non-free" >> /etc/apt/sources.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        build-essential \
        clamav-daemon=${CLAMAV_VERSION}* \
        clamav-freshclam=${CLAMAV_VERSION}* \
        libclamunrar9 \
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

# web server needs access to the clamd socket
RUN usermod -a -G clamav uwsgi

COPY config/freshclam.conf /etc/clamav

COPY config/additional-supervisord.conf /home/vcap/additional-supervisord.conf
RUN cat /home/vcap/additional-supervisord.conf >> /etc/supervisord.conf

COPY config/additional-awslogs.conf /home/vcap/additional-awslogs.conf
RUN cat /home/vcap/additional-awslogs.conf >> /etc/awslogs.conf

COPY config/eicar.ndb.part-a /root/
COPY config/eicar.ndb.part-b /root/
# the contents of this custom virus definition are simply Eicar-Test-Signature:0:*:<literal eicar string in hex>
# and because it contains a literal representation of the eicar string we store it encrypted with a one-time-pad.
RUN python -c 'a = open("/root/eicar.ndb.part-a", "rb"); b = open("/root/eicar.ndb.part-b", "rb"); c = open("/var/lib/clamav/eicar.ndb", "wb"); c.write(bytes(A^B for A, B in zip(a.read(), b.read()))); c.close()'
