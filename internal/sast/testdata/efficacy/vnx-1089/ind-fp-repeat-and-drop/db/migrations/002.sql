CREATE INDEX IF NOT EXISTS idx_t_a ON t (a);
CREATE INDEX IF NOT EXISTS idx_t_b ON t (b);
CREATE INDEX idx_t_i ON t (i);
DROP INDEX idx_t_i;
