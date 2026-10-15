const mysql = require("mysql2/promise");

~>const pool = mysql.createPool("mariadb://api:@@sample:[A-Za-z0-9]{20}@@@maria.acme.internal:3306/api");
