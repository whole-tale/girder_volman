FROM ubuntu:wily

RUN apt-get update -qy && \
   apt-get upgrade -qy && \
   apt-get -qy install python3-requests python3-tornado python3-pycurl &&\
   apt-get -qy install python3-pip &&\
   apt-get -qy clean all && \
   rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt && rm /tmp/requirements.txt

COPY mount.c /tmp/mount.c
RUN cc -Wall -fPIC -shared -o /usr/local/lib/container_mount.so /tmp/mount.c -ldl -D_FILE_OFFSET_BITS=64 && \
   rm  /tmp/mount.c && \
   chmod +x /usr/local/lib/container_mount.so && \
   echo "/usr/local/lib/container_mount.so" > /etc/ld.so.preload

COPY dockworker.py /srv/dockworker.py
COPY main.py /srv/main.py

EXPOSE 9005

WORKDIR /srv

CMD ["python3", "main.py"]
