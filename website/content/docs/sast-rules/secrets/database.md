---
title: "Secrets — Database Credentials"
description: "PostgreSQL, MySQL, MongoDB, Redis and other connection strings with embedded credentials."
weight: 9
---

PostgreSQL, MySQL, MongoDB, Redis and other connection strings with embedded credentials.

All rules in this category are kind `secrets`. They run under `vulnetix secrets` and the secrets stage of `vulnetix scan`.

| Rule ID | Name | Severity | Detection |
|---------|------|----------|-----------|
| <a id="vnx-sec-561"></a>VNX-SEC-561 | Snowflake account identifier + password connection | Critical | keyword + regex |
| <a id="vnx-sec-562"></a>VNX-SEC-562 | Snowflake programmatic access token | Critical | keyword + regex + entropy |
| <a id="vnx-sec-563"></a>VNX-SEC-563 | Databricks personal access token | Critical | keyword + regex |
| <a id="vnx-sec-564"></a>VNX-SEC-564 | PlanetScale service token | Critical | keyword + regex |
| <a id="vnx-sec-565"></a>VNX-SEC-565 | PlanetScale database password | Critical | keyword + regex |
| <a id="vnx-sec-566"></a>VNX-SEC-566 | Neon database connection string | Critical | keyword + regex |
| <a id="vnx-sec-567"></a>VNX-SEC-567 | Neon API key | High | keyword + regex |
| <a id="vnx-sec-568"></a>VNX-SEC-568 | CockroachDB Cloud connection string | Critical | keyword + regex |
| <a id="vnx-sec-569"></a>VNX-SEC-569 | FaunaDB secret key | Critical | keyword + regex |
| <a id="vnx-sec-570"></a>VNX-SEC-570 | InfluxDB v2 API token | High | keyword + regex + entropy |
| <a id="vnx-sec-571"></a>VNX-SEC-571 | InfluxDB v1 user:password connection | High | keyword + regex |
| <a id="vnx-sec-572"></a>VNX-SEC-572 | Elastic Cloud API key (base64) | High | keyword + regex + entropy |
| <a id="vnx-sec-573"></a>VNX-SEC-573 | Elastic Cloud ID | Medium | keyword + regex + entropy |
| <a id="vnx-sec-574"></a>VNX-SEC-574 | MongoDB Atlas API public key | Medium | keyword + regex + entropy |
| <a id="vnx-sec-575"></a>VNX-SEC-575 | MongoDB Atlas API private key | Critical | keyword + regex |
| <a id="vnx-sec-576"></a>VNX-SEC-576 | Upstash Redis REST token | High | keyword + regex + entropy |
| <a id="vnx-sec-577"></a>VNX-SEC-577 | Redis Cloud / rediss URL with password | High | keyword + regex |
| <a id="vnx-sec-578"></a>VNX-SEC-578 | RabbitMQ AMQP URL with credentials | High | keyword + regex |
| <a id="vnx-sec-579"></a>VNX-SEC-579 | Confluent Cloud API key | High | keyword + regex + entropy |
| <a id="vnx-sec-580"></a>VNX-SEC-580 | Confluent Cloud API secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-581"></a>VNX-SEC-581 | Cloudinary URL with API secret | Critical | keyword + regex |
| <a id="vnx-sec-582"></a>VNX-SEC-582 | Mux access token ID | Medium | keyword + regex |
| <a id="vnx-sec-583"></a>VNX-SEC-583 | Mux access token secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-584"></a>VNX-SEC-584 | Bunny CDN API / storage key | High | keyword + regex |
| <a id="vnx-sec-585"></a>VNX-SEC-585 | ImageKit private key | Critical | keyword + regex |
| <a id="vnx-sec-586"></a>VNX-SEC-586 | Filestack API key | High | keyword + regex + entropy |
| <a id="vnx-sec-587"></a>VNX-SEC-587 | Uploadcare secret key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-588"></a>VNX-SEC-588 | Uploadcare public key | Medium | keyword + regex + entropy |
| <a id="vnx-sec-589"></a>VNX-SEC-589 | AWS RDS / Aurora connection string | Critical | keyword + regex |
| <a id="vnx-sec-590"></a>VNX-SEC-590 | ClickHouse connection string with password | High | keyword + regex |
| <a id="vnx-sec-591"></a>VNX-SEC-591 | TimescaleDB Cloud connection string | Critical | keyword + regex |
| <a id="vnx-sec-592"></a>VNX-SEC-592 | SingleStore connection string with password | High | keyword + regex |
| <a id="vnx-sec-593"></a>VNX-SEC-593 | DataStax Astra DB token | Critical | keyword + regex |
| <a id="vnx-sec-594"></a>VNX-SEC-594 | Couchbase connection string with password | High | keyword + regex |
| <a id="vnx-sec-595"></a>VNX-SEC-595 | Neo4j Aura connection string with password | Critical | keyword + regex |
| <a id="vnx-sec-596"></a>VNX-SEC-596 | ArangoDB connection string with password | High | keyword + regex |
| <a id="vnx-sec-597"></a>VNX-SEC-597 | Memcached SASL connection with credentials | Medium | keyword + regex |
| <a id="vnx-sec-598"></a>VNX-SEC-598 | MSSQL connection string with password | Critical | keyword + regex |
| <a id="vnx-sec-599"></a>VNX-SEC-599 | Oracle DB connection string with password | Critical | keyword + regex |
| <a id="vnx-sec-600"></a>VNX-SEC-600 | Cassandra connection string with password | High | keyword + regex |
| <a id="vnx-sec-601"></a>VNX-SEC-601 | Snowflake key-pair private key (JWT auth) | Critical | keyword + regex |
| <a id="vnx-sec-602"></a>VNX-SEC-602 | Databricks OAuth client secret | Critical | keyword + regex |
| <a id="vnx-sec-628"></a>VNX-SEC-628 | Upstash Kafka REST password | High | keyword + regex + entropy |
| <a id="vnx-sec-629"></a>VNX-SEC-629 | MongoDB Atlas SRV connection with password | Critical | keyword + regex |
| <a id="vnx-sec-630"></a>VNX-SEC-630 | Snowflake account locator + region | Medium | keyword + regex |
| <a id="vnx-sec-631"></a>VNX-SEC-631 | Redis Cloud / Upstash REST URL (https with token) | High | keyword + regex |
| <a id="vnx-sec-635"></a>VNX-SEC-635 | ScyllaDB Cloud connection string with password | High | keyword + regex |
| <a id="vnx-sec-636"></a>VNX-SEC-636 | Aiven service connection string with password | Critical | keyword + regex |
| <a id="vnx-sec-637"></a>VNX-SEC-637 | Aiven API token | Critical | keyword + regex |

## Remediation

Rotate any exposed credential immediately, remove it from source, and load it from a secrets manager or environment variable instead. Purge it from git history with `git filter-repo`. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
