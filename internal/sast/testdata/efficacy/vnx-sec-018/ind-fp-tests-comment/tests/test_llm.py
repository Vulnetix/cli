from openai import OpenAI

def test_client():
    c = OpenAI(api_key="sk-proj-@@sample:[A-Za-z0-9_-]{120}@@")
    assert c
