import uvicorn
from fastapi import FastAPI

app = FastAPI(debug=True)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", reload=True)
