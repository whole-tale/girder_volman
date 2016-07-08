FROM ubuntu:xenial

  #apt-get install -qy software-properties-common python-software-properties && \
  #apt-get update && \
RUN apt-get update -qy && \
  apt-get -qy install git fuse libfuse-dev \
    build-essential \
    wget \
    python3 \
    libcurl4-gnutls-dev \
    libgnutls-dev \
    libffi-dev \
    libssl-dev \
    libjpeg-dev \
    zlib1g-dev \
    libpython3-dev && \
  apt-get -qy clean all && \
  echo "user_allow_other" >> /etc/fuse.conf && \
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN wget -q https://bootstrap.pypa.io/get-pip.py && python3 get-pip.py

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt && rm /tmp/requirements.txt

COPY mount.c /tmp/mount.c
RUN gcc -Wall -fPIC -shared -o /usr/local/lib/container_mount.so /tmp/mount.c -ldl -D_FILE_OFFSET_BITS=64 && \
   rm  /tmp/mount.c && \
   chmod +x /usr/local/lib/container_mount.so && \
   echo "/usr/local/lib/container_mount.so" > /etc/ld.so.preload

COPY dockworker.py /srv/dockworker.py
COPY main.py /srv/main.py

EXPOSE 9005

WORKDIR /srv

CMD ["python3", "main.py"]
