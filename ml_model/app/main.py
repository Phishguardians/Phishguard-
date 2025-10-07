from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import email_scan, link_scan, doc_scan, qr_router  # Added QR router

app = FastAPI(title="Internship & Job Scam + QR Scanner API")

# ✅ Allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # later restrict to your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Include routers
app.include_router(email_scan.router, prefix="/scan/email", tags=["Email Scan"])
app.include_router(link_scan.router, prefix="/scan/link", tags=["Phishing Link Scan"])
app.include_router(doc_scan.router, prefix="/scan/doc", tags=["Document Scan"])
app.include_router(qr_router.router, prefix="/scan/qr", tags=["QR Scanner"])  # QR router

@app.get("/")
def read_root():
    return {"message": "Welcome to the Scam Detection + QR Scanner API 🚀"}
