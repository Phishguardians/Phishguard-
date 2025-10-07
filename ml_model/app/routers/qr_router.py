# app/routers/qr_router.py
from fastapi import APIRouter, UploadFile, File, HTTPException
from app.utils.qr_utils import predict_qr

router = APIRouter(
    prefix="/api/qr",
    tags=["QR Scanner"],
)

@router.post("/scan")
async def scan_qr(file: UploadFile = File(...)):
    """
    Scan and analyze QR code from uploaded image.
    Returns prediction: Legit or Phishing
    """
    if not file.filename.lower().endswith((".png", ".jpg", ".jpeg")):
        raise HTTPException(status_code=400, detail="Please upload a valid image file (PNG/JPG).")

    try:
        image_bytes = await file.read()
        result = predict_qr(image_bytes)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"QR scan failed: {str(e)}")
