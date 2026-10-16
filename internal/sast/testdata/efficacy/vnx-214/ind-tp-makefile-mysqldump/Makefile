DB_USER ?= app
DB_NAME ?= shop

.PHONY: backup
backup:
~>	mysqldump -u $(DB_USER) -p$(DB_PASSWORD) $(DB_NAME) > backups/$(DB_NAME).sql
