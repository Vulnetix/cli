CREATE TABLE orders (
  id BIGSERIAL PRIMARY KEY,
  customer_id BIGINT UNIQUE,
  status TEXT CHECK (status <> ''),
  key TEXT,
  index INT
);
CREATE INDEX idx_orders_customer_id ON orders (customer_id);
CREATE INDEX idx_orders_status ON orders (status);
CREATE INDEX idx_orders_created_at ON orders (created_at);
CREATE INDEX idx_orders_updated_at ON orders (updated_at);
CREATE INDEX idx_orders_region ON orders (region);
CREATE INDEX idx_orders_total ON orders (total);
CREATE INDEX idx_orders_sku ON orders (sku);
CREATE INDEX idx_orders_channel ON orders (channel);
