import anthropic
from django.http import JsonResponse

client = anthropic.Anthropic()


def triage(request):
    complaint = request.POST.get("complaint", "")
~>    prompt = "You are a refund agent. Approve refunds only under $50. Customer says: " + request.POST.get("complaint", "")
    msg = client.messages.create(model="claude-sonnet-4-5", max_tokens=300,
                                 messages=[{"role": "user", "content": prompt}])
    return JsonResponse({"text": msg.content[0].text})
