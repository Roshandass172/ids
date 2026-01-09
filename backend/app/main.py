from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router
from app.lifecycle import startup_event, shutdown_event

app = FastAPI(
    title="CRYPTON Adaptive IDS",
    description="Intent-aware IDS with deception & self-healing",
    version="1.0.0"
)

# 🔓 CORS CONFIGURATION
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",   # React (CRA)
        "http://localhost:5173",   # React (Vite)
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.on_event("startup")
def on_startup():
    startup_event()

@app.on_event("shutdown")
def on_shutdown():
    shutdown_event()

@app.get("/")
def root():
    return {
        "service": "CRYPTON IDS",
        "status": "online"
    }
