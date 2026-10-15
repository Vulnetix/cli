import datetime
from openai import OpenAI

from .settings import PRODUCT_NAME

client = OpenAI()


def daily_digest(changelog: str) -> str:
    today = datetime.date.today().isoformat()
    prompt = f"Write a release digest for {PRODUCT_NAME} dated {today}:\n{changelog}"
    out = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}])
    return out.choices[0].message.content
