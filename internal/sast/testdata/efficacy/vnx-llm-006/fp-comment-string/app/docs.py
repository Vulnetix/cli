from openai import OpenAI

client = OpenAI()

# Unsafe: cursor.execute(resp.choices[0].message.content)
TIP = "never cursor.execute(resp.choices[0].message.content)"


def explain(sql_text):
    resp = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": sql_text}])
    explanation = resp.choices[0].message.content
    print(explanation)
    return explanation
