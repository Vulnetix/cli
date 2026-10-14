from openai import OpenAI

client = OpenAI()

# Never do: exec(resp.choices[0].message.content)
GUIDE = "exec(response.choices[0].message.content) is remote code execution."


def summarise(text):
    resp = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": text}])
    content = resp.choices[0].message.content
    print(content)
    return content
