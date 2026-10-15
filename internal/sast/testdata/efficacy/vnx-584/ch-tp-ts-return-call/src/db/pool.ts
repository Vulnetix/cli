export function runQuery(pool: Pool, sql: string): Result {
  const conn = pool.get();
  try {
    return conn.query(sql);
  } finally {
    pool.put(conn);
~>    return cleanup(conn) as Result;
  }
}
