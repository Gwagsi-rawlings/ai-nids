from fastapi import FastAPI

app = FastAPI(title="AI-NIDS", version="1.0.0")


@app.get("/health")
def health_check():
    return {"status": "ok", "system": "AI-NIDS"}
