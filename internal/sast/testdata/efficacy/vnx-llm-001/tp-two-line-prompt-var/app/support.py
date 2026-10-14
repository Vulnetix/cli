import anthropic
from django.http import JsonResponse

client = anthropic.Anthropic()


def ticket_reply(request):
    body = request.POST
    complaint = body.get("complaint", "")
~>    prompt = f"You are a refund agent. Approve refunds only under $50. Customer says: {complaint}"
    msg = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return JsonResponse({"reply": msg.content[0].text})


def classify(user_message):
~>    full_prompt = "Classify the sentiment of this review as positive or negative: " + user_message
    msg = client.messages.create(model="claude-sonnet-4-5", max_tokens=16, messages=[{"role": "user", "content": full_prompt}])
    return msg.content[0].text
