import datetime

import anthropic
from langchain_core.prompts import PromptTemplate

client = anthropic.Anthropic()
TOOLS_DOC = "lookup_order, track_parcel"


def ask(question):
    today = datetime.date.today().isoformat()
    msg = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        system=f"Today is {today}. Available tools: {TOOLS_DOC}.",
        messages=[{"role": "user", "content": question}],
    )
    template = PromptTemplate.from_template("Explain for {audience}: {topic}")
    return msg.content[0].text, template
