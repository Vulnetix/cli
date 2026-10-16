import path from 'path';
const p = path.join(a, b);
// SELECT * FROM a JOIN b ON 1 JOIN c ON 1 JOIN d ON 1 JOIN e ON 1 JOIN f ON 1 JOIN g ON 1
const rows = await knex('a').join('b', 'a.id', 'b.a').join('c', 'b.id', 'c.b').join('d','c.id','d.c').join('e','d.id','e.d').join('f','e.id','f.e');
