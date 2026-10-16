import pandas as pd
from django.http import HttpResponse


def download(request):
    df = pd.DataFrame(list(Comment.objects.values("author", "text")))
    resp = HttpResponse(content_type="text/csv")
    resp["Content-Disposition"] = 'attachment; filename="comments.csv"'
~>    df.to_csv(resp, index=False)
    return resp
