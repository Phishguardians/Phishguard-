# Train AI models
python train/train_email_model.py
python train/train_link_model.py
python train/train_doc_model.py

# Start API server
python -m uvicorn app.main:app --reload