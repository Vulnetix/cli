export async function report(pool, from) {
~>  return pool.query(
    `SELECT day, SUM(total)
       FROM sales
      WHERE day >= '${from}'
      GROUP BY day`
  );
}
