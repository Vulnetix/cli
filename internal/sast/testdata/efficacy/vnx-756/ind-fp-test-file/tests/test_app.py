from fastapi import FastAPI

app = FastAPI(debug=True)


def test_ok():
    assert app
