from django.db import connection
from django.http import JsonResponse
from django.views.decorators.http import require_GET


@require_GET
def revenue_by_month(request):
~>    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT date_trunc('month', created_at) AS month, SUM(total)
        FROM shop_order
        GROUP BY 1 ORDER BY 1
        """
    )
    data = [{"month": m.isoformat(), "total": float(t)} for m, t in cursor.fetchall()]
    return JsonResponse({"revenue": data})
