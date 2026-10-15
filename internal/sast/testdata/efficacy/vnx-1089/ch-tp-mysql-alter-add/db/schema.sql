~>CREATE TABLE orders (
  id BIGINT NOT NULL AUTO_INCREMENT,
  customer_id BIGINT NOT NULL,
  status VARCHAR(20),
  PRIMARY KEY (id),
  KEY idx_customer (customer_id),
  KEY idx_status (status)
);

ALTER TABLE orders ADD INDEX idx_created (created_at);
ALTER TABLE orders ADD INDEX idx_updated (updated_at);
ALTER TABLE orders ADD KEY idx_region (region);
ALTER TABLE `orders` ADD UNIQUE INDEX idx_ref (reference);
ALTER TABLE orders
  ADD INDEX idx_total (total),
  ADD INDEX idx_currency (currency);
ALTER TABLE orders ADD FULLTEXT INDEX idx_notes (notes);
