from fastapi import FastAPI
from app.routes.auth import router as auth_router
from app.database.session import Base, engine

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(auth_router)
