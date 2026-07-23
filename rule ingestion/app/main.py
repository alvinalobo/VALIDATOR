from fastapi import FastAPI
from api.connector_routes import router as connector_router

app = FastAPI(
    title="Rule Ingestion Service",
    version="1.0.0"
)

app.include_router(connector_router)

@app.get("/")
def home():
    return {"message": "Rule Ingestion Service is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}