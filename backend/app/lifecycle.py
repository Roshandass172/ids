import logging

def startup_event():
    logging.info("🚀 FastAPI server started")

def shutdown_event():
    logging.info("🛑 FastAPI server shutting down")
