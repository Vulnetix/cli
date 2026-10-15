~>CREATE TABLE orders (
    id BIGSERIAL PRIMARY KEY,
    customer_id BIGINT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    region TEXT,
    channel TEXT,
    total NUMERIC(12,2),
    coupon TEXT,
    ref TEXT
);

CREATE INDEX idx_orders_customer ON orders (customer_id);
CREATE INDEX idx_orders_status ON orders (status);
create index idx_orders_created on orders(created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_upd ON public.orders USING btree (updated_at);
CREATE INDEX CONCURRENTLY idx_orders_region ON orders (region);
CREATE INDEX idx_orders_channel
    ON orders (channel);
CREATE INDEX idx_orders_total ON "orders" (total);
CREATE INDEX idx_orders_coupon ON orders (coupon);
CREATE INDEX idx_orders_ref ON orders (ref);
