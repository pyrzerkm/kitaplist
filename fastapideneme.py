from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.orm import Session

from database import SessionLocal, engine
from models import KitapModel
from models import Base  # Veritabanı tablolarını oluşturmak için

# Sabit kategoriler
SABIT_KATEGORILER = [
    "Bilim ve Mühendislik",
    "Çocuk Kitapları",
    "Açık Kaynak Kitapları",
    "Dil Kitapları",
    "Tarih Kitapları"
]

# Veritabanı tablolarını oluştur
Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic modeller
class KitapEkle(BaseModel):
    baslik: str
    yazar: str
    yayin_yili: int
    sayfa_sayisi: int
    tur: Optional[str] = "Bilinmiyor"
    kategori: str

    def validate(self):
        if self.kategori not in SABIT_KATEGORILER:
            raise ValueError("Geçersiz kategori seçildi.")

class Kitap(KitapEkle):
    id: int
    favori: bool = False

    class Config:
        orm_mode = True

# --- API Rotaları ---
@app.get("/")
def anasayfa():
    return {"mesaj": "📚 Kitap API'ye hoş geldin!"}

@app.get("/kitaplar/", response_model=List[Kitap])
def kitaplari_listele(db: Session = Depends(get_db)):
    return db.query(KitapModel).all()

@app.get("/kitaplar/favoriler/", response_model=List[Kitap])
def favori_kitaplari_getir(db: Session = Depends(get_db)):
    return db.query(KitapModel).filter(KitapModel.favori == True).all()

@app.post("/kitap-ekle/", response_model=Kitap)
def kitap_ekle(kitap: KitapEkle, db: Session = Depends(get_db)):
    try:
        kitap.validate()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    yeni_kitap = KitapModel(**kitap.dict())
    db.add(yeni_kitap)
    db.commit()
    db.refresh(yeni_kitap)
    return yeni_kitap

@app.get("/kitap/{kitap_id}", response_model=Kitap)
def kitap_getir(kitap_id: int, db: Session = Depends(get_db)):
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Kitap bulunamadı!")
    return kitap

@app.delete("/kitap-sil/{kitap_id}")
def kitap_sil(kitap_id: int, db: Session = Depends(get_db)):
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Kitap silinemedi, ID bulunamadı.")
    db.delete(kitap)
    db.commit()
    return {"mesaj": f"{kitap_id} numaralı kitap silindi."}

@app.put("/kitap-guncelle/{kitap_id}", response_model=Kitap)
def kitap_guncelle(kitap_id: int, guncel_kitap: KitapEkle, db: Session = Depends(get_db)):
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Güncellenecek kitap bulunamadı.")
    try:
        guncel_kitap.validate()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    for field, value in guncel_kitap.dict().items():
        setattr(kitap, field, value)

    db.commit()
    db.refresh(kitap)
    return kitap

@app.post("/kitap/{kitap_id}/favori/")
def favori_yap(kitap_id: int, db: Session = Depends(get_db)):
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Kitap bulunamadı!")
    if kitap.favori:
        raise HTTPException(status_code=400, detail="Zaten favorilerde.")
    kitap.favori = True
    db.commit()
    return {"mesaj": f"{kitap.baslik} favorilere eklendi."}

@app.post("/kitap/{kitap_id}/favori-kaldir/")
def favori_kaldir(kitap_id: int, db: Session = Depends(get_db)):
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Kitap bulunamadı!")
    if not kitap.favori:
        raise HTTPException(status_code=400, detail="Kitap favorilerde değil.")
    kitap.favori = False
    db.commit()
    return {"mesaj": f"{kitap.baslik} favorilerden çıkarıldı."}
