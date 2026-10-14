<?php

namespace App\Repositories;

use Illuminate\Support\Facades\DB;

class SalesReport
{
    public function monthly(int $year): array
    {
        // Previous implementation, kept for reference while the view is rebuilt:
        // $rows = collect(fetchAll())->map(fn ($r) => normalise($r))->filter(isPaid(...));
        // return summarise(group(sortBy($rows, 'month')), currencyOf(account()));
        $sql = "SELECT EXTRACT(MONTH FROM paid_at) AS month,
                       COUNT(*) AS orders,
                       SUM(total) AS revenue,
                       AVG(total) AS average,
                       MIN(total) AS smallest,
                       MAX(total) AS largest,
                       COALESCE(SUM(refunded), 0) AS refunds,
                       ROUND(STDDEV(total), 2) AS spread,
                       COUNT(DISTINCT customer_id) AS customers,
                       DATE_TRUNC('month', paid_at) AS bucket,
                       LOWER(TRIM(region)) AS region,
                       UPPER(SUBSTRING(currency, 1, 3)) AS currency,
                       NULLIF(discount, 0) AS discount,
                       GREATEST(shipping, 0) AS shipping,
                       LEAST(tax, total) AS tax,
                       CAST(margin AS NUMERIC(10, 2)) AS margin,
                       PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY total) AS median,
                       STRING_AGG(sku, ',') AS skus,
                       ARRAY_AGG(order_id) AS ids,
                       BOOL_OR(flagged) AS any_flagged,
                       ABS(c0) AS x0,
                       CEIL(c1) AS x1,
                       FLOOR(c2) AS x2,
                       SIGN(c3) AS x3,
                       SQRT(c4) AS x4,
                       POWER(c5) AS x5,
                       EXP(c6) AS x6,
                       LN(c7) AS x7,
                       LOG10(c8) AS x8,
                       MOD(c9) AS x9,
                       TRUNC(c10) AS x10,
                       LENGTH(c11) AS x11,
                       REVERSE(c12) AS x12,
                       MD5(c13) AS x13,
                       INITCAP(c14) AS x14,
                       LPAD(c15) AS x15,
                       RPAD(c16) AS x16,
                       REPLACE(c17) AS x17,
                       TRANSLATE(c18) AS x18,
                       TO_CHAR(c19) AS x19,
                       TO_DATE(c20) AS x20,
                       AGE(c21) AS x21,
                       NOW(c22) AS x22,
                       JUSTIFY_DAYS(c23) AS x23,
                       ISFINITE(c24) AS x24,
                       JSON_BUILD_OBJECT('n', COUNT(*)) AS meta
                  FROM orders
                 WHERE EXTRACT(YEAR FROM paid_at) = ?
              GROUP BY 1, bucket, region, currency
              ORDER BY 1";
        $rows = DB::select($sql, [$year]);
        return array_map(fn ($row) => (array) $row, $rows);
    }
}
