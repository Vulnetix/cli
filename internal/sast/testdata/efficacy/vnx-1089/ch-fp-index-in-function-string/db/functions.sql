CREATE OR REPLACE FUNCTION make_partition(p text) RETURNS void AS $$
BEGIN
  EXECUTE format('CREATE INDEX %I ON %I (a)', p || '_a', p);
  EXECUTE format('CREATE INDEX %I ON %I (b)', p || '_b', p);
END;
$$ LANGUAGE plpgsql;

CREATE INDEX events_a ON events (a);
CREATE INDEX events_b ON events (b);
CREATE INDEX events_c ON events (c);
-- CREATE INDEX events_d ON events (d);
-- CREATE INDEX events_e ON events (e);
/* CREATE INDEX events_f ON events (f);
CREATE INDEX events_g ON events (g);
CREATE INDEX events_h ON events (h);
CREATE INDEX events_i ON events (i);
CREATE INDEX events_j ON events (j);
CREATE INDEX events_k ON events (k);
CREATE INDEX events_l ON events (l);
CREATE INDEX events_m ON events (m); */
