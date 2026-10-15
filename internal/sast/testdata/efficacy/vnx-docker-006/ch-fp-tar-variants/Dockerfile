FROM scratch
ADD rootfs.tar.xz /
ADD --link vendor.tgz /opt/vendor/
ADD assets.tar.bz2 /srv/assets/
ADD https://dl.example.com/tool.tar.gz /tmp/
COPY . /app
