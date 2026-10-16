import datetime
from openai import OpenAI

client = OpenAI()
TOOLS = ["search", "calendar"]


def ask(question):
    today = datetime.date.today().isoformat()
    system = f"You are a helpful assistant. Today is {today}. Tools: {', '.join(TOOLS)}."
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": system}, {"role": "user", "content": question}],
    )
