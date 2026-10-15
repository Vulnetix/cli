CREATE TABLE orders (
  id BIGINT NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (id),
  KEY idx_a (a),
  KEY idx_b (b),
  KEY idx_c (c),
  KEY idx_d (d),
  KEY idx_e (e),
  KEY idx_f (f)
);

ALTER TABLE orders ADD INDEX idx_g (g);
ALTER TABLE orders ADD INDEX idx_h (h);
ALTER TABLE orders ADD INDEX idx_i (i);
ALTER TABLE orders DROP INDEX idx_a;
ALTER TABLE orders DROP INDEX idx_b, DROP INDEX idx_c;
