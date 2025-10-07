from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import email_scan, link_scan, doc_scan

app = FastAPI(title="Internship & Job Scam Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(email_scan.router, prefix="/scan/email", tags=["Email Scan"])
app.include_router(link_scan.router, prefix="/scan/link", tags=["Phishing Link Scan"])
app.include_router(doc_scan.router, prefix="/scan/doc", tags=["Document Scan"])


@app.get("/")
def read_root():
    return {"message": "Welcome to the Scam Detection API"}
