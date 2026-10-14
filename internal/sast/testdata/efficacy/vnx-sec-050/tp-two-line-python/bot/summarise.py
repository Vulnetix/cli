from google import genai

~>API_KEY = "AIza@@sample:[A-Za-z0-9_-]{35}@@"

client = genai.Client(api_key=API_KEY)
reply = client.models.generate_content(model="gemini-2.0-flash", contents="hi")
