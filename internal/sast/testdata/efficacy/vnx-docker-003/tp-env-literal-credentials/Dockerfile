FROM postgres:16.3
~>ENV POSTGRES_PASSWORD=Sup3rS3cret-prod
~>ENV DB_PASS hunter2-reporting
~>ENV API_KEY="k8s-orders-cf658c56a5013852"
~>env client_secret='8f3a1c0e9b7d4e2a'
COPY init.sql /docker-entrypoint-initdb.d/
