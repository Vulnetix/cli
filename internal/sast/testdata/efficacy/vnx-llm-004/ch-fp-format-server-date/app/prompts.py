import datetime

SYSTEM_PROMPT = "You are a scheduling assistant. Today is {today}."


def system_prompt():
    return SYSTEM_PROMPT.format(today=datetime.date.today().isoformat())
