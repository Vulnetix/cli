FROM eclipse-temurin:21-jre-jammy
~>ONBUILD ADD . /usr/src/app
~>ADD target/*.jar /opt/app/
~>ADD scripts/entrypoint.sh rootfs.tar.gz /opt/
ENTRYPOINT ["/opt/entrypoint.sh"]
