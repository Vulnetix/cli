~>CREATE TABLE `logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `a` int, `b` int, `c` int, `d` int, `e` int, `f` int, `g` int, `h` int, `body` text,
  PRIMARY KEY (`id`),
  KEY `k_a` (`a`),
  KEY `k_b` (`b`),
  INDEX `k_c` (`c`),
  UNIQUE KEY `k_d` (`d`),
  KEY `k_e` (`e`),
  KEY `k_f` (`f`),
  KEY `k_g` (`g`),
  FULLTEXT KEY `k_body` (`body`),
  KEY `k_h` (`h`)
) ENGINE=InnoDB;
