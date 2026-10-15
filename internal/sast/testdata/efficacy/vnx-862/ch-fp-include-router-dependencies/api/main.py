from fastapi import Depends, FastAPI

from . import admin
from .security import get_current_admin

app = FastAPI()
app.include_router(
    admin.router,
    dependencies=[Depends(get_current_admin)],
)
