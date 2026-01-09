from fastapi import APIRouter
import monitor

router = APIRouter(
    prefix="/ids",
    tags=["IDS Control"]
)

@router.post("/start")
def start_ids():
    monitor.start_ids()
    return {"status": "IDS started"}

@router.post("/stop")
def stop_ids():
    monitor.stop_ids()
    return {"status": "IDS stop requested"}

@router.get("/status")
def ids_status():
    return monitor.ids_status()
