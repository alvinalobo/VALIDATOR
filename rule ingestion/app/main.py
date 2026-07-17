from fastapi import FastAPI

app= FastAPI(
    title="Rule Ingestion Service",
    version="1.0.0"
)

@app.get("/")
def home():
    return {"message": "Rule Ingestion Service is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}