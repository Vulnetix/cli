CREATE TABLE accounts (id int primary key, a int, b int, c int, d int, e int, f int, g int, h int, i int);
CREATE INDEX ia ON accounts (a);
CREATE INDEX ib ON accounts (b);
-- CREATE INDEX ic ON accounts (c);
-- CREATE INDEX id_ ON accounts (d);
/* CREATE INDEX ie ON accounts (e);
   CREATE INDEX if_ ON accounts (f);
   CREATE INDEX ig ON accounts (g); */
INSERT INTO accounts (a) VALUES ('CREATE INDEX ih ON accounts (h); CREATE INDEX ii ON accounts (i); CREATE INDEX ij ON accounts (a,b)');
CREATE INDEX ik ON accounts (a, b);
CREATE INDEX il ON accounts (b, c);
CREATE INDEX im ON accounts (c, d);
CREATE INDEX in_ ON accounts (d, e);
