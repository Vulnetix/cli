FROM mysql:8.0
ARG @@sample:M[Y]SQ[L][_]R[O]OT[_]PA[S]SW[O]RD@@
COPY schema.sql /docker-entrypoint-initdb.d/
~>RUN mysqld --initialize-insecure && mysql -uroot -p$MYSQL_ROOT_PASSWORD < /docker-entrypoint-initdb.d/schema.sql
