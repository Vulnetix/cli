<?php

namespace App\Reports;

use PDO;

final class RevenueReport
{
    public function __construct(private PDO $db)
    {
    }

    public function monthly(int $year): array
    {
        $sql = <<<SQL
            SELECT DATE_TRUNC('month', o.created_at) AS month,
                   COUNT(DISTINCT o.id) AS orders,
                   SUM(o.total_cents) AS gross,
                   AVG(o.total_cents) AS average,
                   MIN(o.total_cents) AS smallest,
                   MAX(o.total_cents) AS largest,
                   COALESCE(SUM(r.amount_cents), 0) AS refunded,
                   ROUND(STDDEV(o.total_cents), 2) AS spread,
                   PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY o.total_cents) AS median,
                   STRING_AGG(DISTINCT UPPER(o.currency), ',') AS currencies,
                   ARRAY_AGG(DISTINCT LOWER(c.country)) AS countries,
                   NULLIF(COUNT(r.id), 0) AS refunds,
                   GREATEST(MAX(o.updated_at), MAX(r.created_at)) AS last_change,
                   LEAST(MIN(o.created_at), MIN(r.created_at)) AS first_seen,
                   EXTRACT(DOW FROM MIN(o.created_at)) AS first_dow,
                   TO_CHAR(MAX(o.created_at), 'YYYY-MM-DD') AS last_day,
                   LENGTH(TRIM(MAX(c.name))) AS longest_name,
                   CONCAT(LEFT(MAX(c.name), 1), RIGHT(MAX(c.name), 1)) AS initials,
                   ABS(SUM(o.discount_cents)) AS discounts,
                   CEIL(AVG(o.items)) AS items,
                   FLOOR(AVG(o.weight_grams)) AS weight,
                   BOOL_OR(o.flagged) AS any_flagged,
                   JSONB_AGG(JSONB_BUILD_OBJECT('id', o.id)) AS ids,
                   MD5(STRING_AGG(o.id::text, '')) AS fingerprint,
                   NOW() AS generated_at,
                   SUBSTRING(MAX(o.notes), 1, 40) AS note,
                   REPLACE(MAX(o.channel), '_', ' ') AS channel,
                   SPLIT_PART(MAX(c.email), '@', 2) AS domain,
                   AGE(MAX(o.created_at), MIN(o.created_at)) AS span,
                   DATE_PART('week', MAX(o.created_at)) AS week,
                   CAST(SUM(o.tax_cents) AS BIGINT) AS tax,
                   REGEXP_REPLACE(MAX(o.sku), '[^A-Z]', '') AS sku_prefix
              FROM orders o
              JOIN customers c ON c.id = o.customer_id
         LEFT JOIN refunds r ON r.order_id = o.id
             WHERE EXTRACT(YEAR FROM o.created_at) = :year
          GROUP BY 1
          ORDER BY 1
        SQL;

        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':year', $year, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $out = [];
        foreach ($rows as $row) {
            $out[] = array_map('intval', array_filter($row, 'is_numeric'));
        }
        return array_values($out);
    }
}
