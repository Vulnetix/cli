~>create table events (
  id int primary key,
  a int, b int, c int, d int, e int, f int, g int, h int, i int
);
CREATE INDEX idx_events_a ON events (a);
CREATE INDEX idx_events_b ON events (b);
CREATE INDEX idx_events_c ON events (c);
CREATE INDEX idx_events_d ON events (d);
CREATE INDEX idx_events_e ON events (e);
