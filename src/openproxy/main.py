from fastapi import FastAPI

app = FastAPI(
    title="OpenProxy",
    description="OpenProxy is a free and open-source proxy server that allows you control your network",
    version="0.1.0",
)

@app.get("/")
async def root():
    return {
        "name": "OpenProxy",
        "status": "development",
        "local": "true"
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy"
    }