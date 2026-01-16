from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

# Настройка
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="IoT Network Guardian", version="1.0.0")

#
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "name": "IoT Network Guardian",
        "version": "1.0.0",
        "status": "active"
    }

@app.get("/api/status")
async def get_status():
    return {"status": "operational"}
