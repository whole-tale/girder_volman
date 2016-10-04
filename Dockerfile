FROM ubuntu:xenial

  #apt-get install -qy software-properties-common python-software-properties && \
  #apt-get update && \
RUN apt-get update -qy && \
  apt-get -qy install git fuse libfuse-dev \
    build-essential \
    wget \
    libcurl4-gnutls-dev \
    libgnutls-dev \
    libffi-dev \
    libssl-dev \
    libjpeg-dev \
    zlib1g-dev && \
  apt-get -qy clean all && \
  echo "user_allow_other" >> /etc/fuse.conf && \
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN wget -q https://repo.continuum.io/miniconda/Miniconda-latest-Linux-x86_64.sh && \
  bash Miniconda-latest-Linux-x86_64.sh -bf && \
  echo 'export PATH=$HOME/miniconda2/bin:$PATH' >> $HOME/.bashrc && \
  $HOME/miniconda2/bin/conda update -q -y --prefix $HOME/miniconda2 conda && \
  $HOME/miniconda2/bin/conda install -q -y git pycurl && \
  rm -rf Miniconda-latest-Linux-x86_64.sh

COPY requirements.txt /tmp/requirements.txt
RUN $HOME/miniconda2/bin/pip install -r /tmp/requirements.txt && \
  rm /tmp/requirements.txt

COPY mount.c /tmp/mount.c
RUN gcc -Wall -fPIC -shared -o /usr/local/lib/container_mount.so /tmp/mount.c -ldl -D_FILE_OFFSET_BITS=64 && \
   rm  /tmp/mount.c && \
   chmod +x /usr/local/lib/container_mount.so && \
   echo "/usr/local/lib/container_mount.so" > /etc/ld.so.preload

COPY dockworker.py /srv/dockworker.py
COPY main.py /srv/main.py
COPY mount_helper.py /srv/mount_helper.py

RUN chmod +x /srv/mount_helper.py

EXPOSE 9005

WORKDIR /srv

CMD ["/root/miniconda2/bin/python", "main.py"]
