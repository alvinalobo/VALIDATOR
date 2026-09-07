
from fastapi import FastAPI
from app.api.connector_routes import router as connector_router
from app.api.rules import router as rule_router
from app.connector.plugin_loader import load_plugins

app = FastAPI(
    title="Rule Ingestion Service",
    version="1.0.0"
)

load_plugins()

app.include_router(connector_router)
app.include_router(rule_router)

@app.get("/")
def home():
    return {"message": "Rule Ingestion Service is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}
