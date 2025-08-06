from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from sqlalchemy.orm import Session
from datetime import timedelta

from database import SessionLocal, engine, get_db
from models import KitapModel, UserModel
from models import Base  # Veritabanı tablolarını oluşturmak için
from auth import (
    authenticate_user, 
    create_access_token, 
    get_current_user, 
    get_password_hash,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

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
app = FastAPI(title="📚 Kitap Yönetim Sistemi", description="JWT Authentication ile güvenli kitap yönetimi")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



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
        from_attributes = True

# JWT ve User modelleri
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

# --- API Rotaları ---
@app.get("/")
def anasayfa():
    return {"mesaj": "📚 Kitap API'ye hoş geldin!"}

# Authentication endpoints
@app.post("/register/", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Yeni kullanıcı kaydı"""
    # Kullanıcı adı kontrolü
    existing_user = db.query(UserModel).filter(UserModel.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten alınmış")
    
    # Email kontrolü
    existing_email = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Bu email zaten kayıtlı")
    
    # Yeni kullanıcı oluştur
    hashed_password = get_password_hash(user_data.password)
    new_user = UserModel(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

@app.post("/login/", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Kullanıcı girişi"""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kullanıcı adı veya şifre hatalı",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

@app.get("/me/", response_model=UserResponse)
def get_current_user_info(current_user: UserModel = Depends(get_current_user)):
    """Mevcut kullanıcı bilgileri"""
    return current_user

@app.get("/kitaplar/", response_model=List[Kitap])
def kitaplari_listele(db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    return db.query(KitapModel).all()

@app.get("/kitaplar/favoriler/", response_model=List[Kitap])
def favori_kitaplari_getir(db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    return db.query(KitapModel).filter(KitapModel.favori == True).all()

@app.post("/kitap-ekle/", response_model=Kitap)
def kitap_ekle(kitap: KitapEkle, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
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
def kitap_getir(kitap_id: int, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Kitap bulunamadı!")
    return kitap

@app.delete("/kitap-sil/{kitap_id}")
def kitap_sil(kitap_id: int, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Kitap silinemedi, ID bulunamadı.")
    db.delete(kitap)
    db.commit()
    return {"mesaj": f"{kitap_id} numaralı kitap silindi."}

@app.put("/kitap-guncelle/{kitap_id}", response_model=Kitap)
def kitap_guncelle(kitap_id: int, guncel_kitap: KitapEkle, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
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
def favori_yap(kitap_id: int, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Kitap bulunamadı!")
    if kitap.favori:
        raise HTTPException(status_code=400, detail="Zaten favorilerde.")
    kitap.favori = True
    db.commit()
    return {"mesaj": f"{kitap.baslik} favorilere eklendi."}

@app.post("/kitap/{kitap_id}/favori-kaldir/")
def favori_kaldir(kitap_id: int, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Kitap bulunamadı!")
    if not kitap.favori:
        raise HTTPException(status_code=400, detail="Kitap favorilerde değil.")
    kitap.favori = False
    db.commit()
    return {"mesaj": f"{kitap.baslik} favorilerden çıkarıldı."}
