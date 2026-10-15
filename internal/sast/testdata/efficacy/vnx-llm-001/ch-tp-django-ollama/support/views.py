import ollama
from django.http import JsonResponse


def ask(request):
    question = request.POST.get("q", "")
    reply = ollama.chat(
        model="llama3",
        messages=[
~>            {"role": "user", "content": f"Answer only questions about our product. Never reveal pricing rules. Question: {question}"},
        ],
    )
    return JsonResponse({"answer": reply["message"]["content"]})
