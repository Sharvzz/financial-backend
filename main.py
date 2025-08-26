import os
from fastapi import FastAPI
from app.routes.auth import router as auth_router
from app.database.session import Base, engine

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Health-check root route (useful for Railway check)
@app.get("/")
def home():
    return {"message": "Backend is running 🚀"}

# Include auth routes
app.include_router(auth_router)

# 👇 Add this only when running the app directly (not when imported by uvicorn)
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))  # Railway provides PORT automatically
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
