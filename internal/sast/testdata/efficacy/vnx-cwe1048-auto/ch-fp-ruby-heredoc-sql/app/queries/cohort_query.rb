class CohortQuery
  def initialize(relation = User.all)
    @relation = relation
  end

  def call(since:)
    sql = <<~SQL
      SELECT DATE_TRUNC('week', u.created_at) AS cohort,
             COUNT(*) AS signups,
             COUNT(DISTINCT s.user_id) AS active,
             SUM(CASE WHEN s.paid THEN 1 ELSE 0 END) AS paid,
             AVG(EXTRACT(EPOCH FROM (s.first_at - u.created_at))) AS ttfa,
             MIN(s.first_at) AS first_activity,
             MAX(s.last_at) AS last_activity,
             COALESCE(ROUND(AVG(s.sessions), 1), 0) AS sessions,
             STRING_AGG(DISTINCT LOWER(u.plan), ',') AS plans,
             ARRAY_AGG(DISTINCT UPPER(u.country)) AS countries,
             PERCENTILE_DISC(0.9) WITHIN GROUP (ORDER BY s.sessions) AS p90,
             NULLIF(SUM(s.refunds), 0) AS refunds,
             GREATEST(MAX(s.last_at), MAX(u.updated_at)) AS touched,
             LEAST(MIN(s.first_at), MIN(u.created_at)) AS earliest,
             TO_CHAR(MAX(u.created_at), 'IYYY-IW') AS iso_week,
             LENGTH(TRIM(MAX(u.name))) AS name_len,
             CONCAT(LEFT(MAX(u.name), 1), RIGHT(MAX(u.name), 1)) AS initials,
             ABS(SUM(s.balance)) AS balance,
             CEIL(AVG(s.pages)) AS pages,
             FLOOR(AVG(s.minutes)) AS minutes,
             BOOL_AND(u.confirmed) AS all_confirmed,
             JSONB_AGG(JSONB_BUILD_OBJECT('id', u.id)) AS ids,
             SPLIT_PART(MAX(u.email), '@', 2) AS domain,
             AGE(MAX(s.last_at), MIN(s.first_at)) AS lifetime,
             DATE_PART('dow', MIN(u.created_at)) AS dow,
             CAST(SUM(s.revenue) AS BIGINT) AS revenue,
             REGEXP_REPLACE(MAX(u.referrer), '^https?://', '') AS referrer,
             MD5(STRING_AGG(u.id::text, '')) AS digest,
             SUBSTRING(MAX(u.bio), 1, 20) AS bio,
             NOW() AS generated_at
        FROM users u
   LEFT JOIN user_stats s ON s.user_id = u.id
       WHERE u.created_at >= :since
    GROUP BY 1
    ORDER BY 1
    SQL

    rows = ActiveRecord::Base.connection.select_all(
      ActiveRecord::Base.sanitize_sql([sql, { since: since }])
    )
    rows.map { |r| r.transform_keys(&:to_sym) }
  end
end
