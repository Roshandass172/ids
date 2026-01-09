from fastapi import FastAPI
from app.api import router
from app.lifecycle import startup_event, shutdown_event

app = FastAPI(
    title="CRYPTON Adaptive IDS",
    description="Intent-aware IDS with deception & self-healing",
    version="1.0.0"
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
