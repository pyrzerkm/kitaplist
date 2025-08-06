from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
import calendar

from database import SessionLocal, engine, get_db
from models import KitapModel, UserModel, KategoriModel, KiralamaModel
from models import Base  # Veritabanı tablolarını oluşturmak için
from auth import (
    authenticate_user, 
    create_access_token, 
    get_current_user, 
    get_password_hash,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# Admin yetki kontrolü
def check_admin_permission(current_user: UserModel):
    """Admin yetkisi kontrolü"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bu işlem için admin yetkisi gerekiyor"
        )

# Kategori yönetimi için yardımcı fonksiyon
def get_active_categories(db: Session):
    """Aktif kategorileri getir"""
    return db.query(KategoriModel).filter(KategoriModel.is_active == True).all()

# Veritabanı tablolarını oluştur
Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI(title="📚 Kütüphane Yönetim Sistemi", description="JWT Authentication ile güvenli kütüphane yönetimi")

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
    aciklama: Optional[str] = None
    stok_adedi: int = 1
    kiralanabilir: bool = True

    def validate(self, db: Session):
        # Kategori kontrolü - veritabanından kontrol et
        kategori = db.query(KategoriModel).filter(
            KategoriModel.ad == self.kategori,
            KategoriModel.is_active == True
        ).first()
        if not kategori:
            # Kategorileri listele ve hata mesajında göster
            mevcut_kategoriler = db.query(KategoriModel).filter(KategoriModel.is_active == True).all()
            kategori_listesi = ", ".join([k.ad for k in mevcut_kategoriler])
            raise ValueError(f"Geçersiz kategori seçildi. Mevcut kategoriler: {kategori_listesi}")

class Kitap(KitapEkle):
    id: int
    favori: bool = False
    kiralanmis: bool = False  # Kiralama durumu

    class Config:
        from_attributes = True

# JWT ve User modelleri
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    ad: Optional[str] = None
    soyad: Optional[str] = None
    telefon: Optional[str] = None
    adres: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    is_admin: bool
    ad: Optional[str]
    soyad: Optional[str]
    telefon: Optional[str]

    class Config:
        from_attributes = True

class KategoriCreate(BaseModel):
    ad: str
    aciklama: Optional[str] = None

class KategoriResponse(BaseModel):
    id: int
    ad: str
    aciklama: Optional[str]
    is_active: bool

    class Config:
        from_attributes = True

class KiralamaCreate(BaseModel):
    kitap_id: int
    beklenen_iade_tarihi: datetime
    notlar: Optional[str] = None

class KiralamaResponse(BaseModel):
    id: int
    kitap_id: int
    kullanici_id: int
    kiralama_tarihi: datetime
    iade_tarihi: Optional[datetime]
    beklenen_iade_tarihi: datetime
    durum: str
    notlar: Optional[str]
    kitap_baslik: str
    kullanici_username: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

# --- API Rotaları ---
@app.get("/")
def anasayfa():
    return {"mesaj": "📚 Kütüphane API'ye hoş geldin!"}

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
        hashed_password=hashed_password,
        ad=user_data.ad,
        soyad=user_data.soyad,
        telefon=user_data.telefon,
        adres=user_data.adres
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

# Admin endpoint'leri
@app.get("/admin/kategoriler/", response_model=List[KategoriResponse])
def kategorileri_listele(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Tüm kategorileri listele (Admin)"""
    check_admin_permission(current_user)
    return db.query(KategoriModel).all()

@app.post("/admin/kategori-ekle/", response_model=KategoriResponse)
def kategori_ekle(
    kategori: KategoriCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Yeni kategori ekle (Admin)"""
    check_admin_permission(current_user)
    
    # Kategori adı kontrolü
    existing_kategori = db.query(KategoriModel).filter(KategoriModel.ad == kategori.ad).first()
    if existing_kategori:
        raise HTTPException(status_code=400, detail="Bu kategori adı zaten mevcut")
    
    yeni_kategori = KategoriModel(**kategori.dict())
    db.add(yeni_kategori)
    db.commit()
    db.refresh(yeni_kategori)
    return yeni_kategori

@app.put("/admin/kategori-guncelle/{kategori_id}", response_model=KategoriResponse)
def kategori_guncelle(
    kategori_id: int,
    kategori_data: KategoriCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Kategori güncelle (Admin)"""
    check_admin_permission(current_user)
    
    kategori = db.query(KategoriModel).filter(KategoriModel.id == kategori_id).first()
    if not kategori:
        raise HTTPException(status_code=404, detail="Kategori bulunamadı")
    
    # Aynı isimde başka kategori var mı kontrol et
    existing_kategori = db.query(KategoriModel).filter(
        KategoriModel.ad == kategori_data.ad,
        KategoriModel.id != kategori_id
    ).first()
    if existing_kategori:
        raise HTTPException(status_code=400, detail="Bu kategori adı zaten mevcut")
    
    kategori.ad = kategori_data.ad
    kategori.aciklama = kategori_data.aciklama
    db.commit()
    db.refresh(kategori)
    return kategori

@app.delete("/admin/kategori-sil/{kategori_id}")
def kategori_sil(
    kategori_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Kategori sil (Admin)"""
    check_admin_permission(current_user)
    
    kategori = db.query(KategoriModel).filter(KategoriModel.id == kategori_id).first()
    if not kategori:
        raise HTTPException(status_code=404, detail="Kategori bulunamadı")
    
    # Bu kategoriyi kullanan kitaplar var mı kontrol et
    kitaplar = db.query(KitapModel).filter(KitapModel.kategori == kategori.ad).count()
    if kitaplar > 0:
        raise HTTPException(
            status_code=400, 
            detail=f"Bu kategori {kitaplar} kitap tarafından kullanılıyor. Önce kitapları başka kategoriye taşıyın."
        )
    
    db.delete(kategori)
    db.commit()
    return {"mesaj": f"'{kategori.ad}' kategorisi silindi"}

@app.get("/admin/istatistikler/")
def admin_istatistikler(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Sistem istatistikleri (Admin)"""
    check_admin_permission(current_user)
    
    toplam_kitap = db.query(KitapModel).count()
    toplam_kullanici = db.query(UserModel).count()
    toplam_kategori = db.query(KategoriModel).count()
    favori_kitap = db.query(KitapModel).filter(KitapModel.favori == True).count()
    kiralanmis_kitap = db.query(KiralamaModel).filter(KiralamaModel.durum == "kiralandi").count()
    gecikmis_kitap = db.query(KiralamaModel).filter(
        KiralamaModel.durum == "kiralandi",
        KiralamaModel.beklenen_iade_tarihi < datetime.now()
    ).count()
    
    return {
        "toplam_kitap": toplam_kitap,
        "toplam_kullanici": toplam_kullanici,
        "toplam_kategori": toplam_kategori,
        "favori_kitap": favori_kitap,
        "kiralanmis_kitap": kiralanmis_kitap,
        "gecikmis_kitap": gecikmis_kitap
    }

@app.get("/admin/kullanicilar/", response_model=List[UserResponse])
def kullanicilari_listele(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Tüm kullanıcıları listele (Admin)"""
    check_admin_permission(current_user)
    return db.query(UserModel).all()

@app.get("/admin/kiralamalar/", response_model=List[KiralamaResponse])
def kiralamalari_listele(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Tüm kiralamaları listele (Admin)"""
    check_admin_permission(current_user)
    
    kiralamalar = db.query(KiralamaModel).all()
    result = []
    for kiralama in kiralamalar:
        result.append(KiralamaResponse(
            id=kiralama.id,
            kitap_id=kiralama.kitap_id,
            kullanici_id=kiralama.kullanici_id,
            kiralama_tarihi=kiralama.kiralama_tarihi,
            iade_tarihi=kiralama.iade_tarihi,
            beklenen_iade_tarihi=kiralama.beklenen_iade_tarihi,
            durum=kiralama.durum,
            notlar=kiralama.notlar,
            kitap_baslik=kiralama.kitap.baslik,
            kullanici_username=kiralama.kullanici.username
        ))
    return result

@app.post("/admin/kitap-iade/{kiralama_id}")
def kitap_iade(
    kiralama_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    check_admin_permission(current_user)
    
    kiralama = db.query(KiralamaModel).filter(KiralamaModel.id == kiralama_id).first()
    if not kiralama:
        raise HTTPException(status_code=404, detail="Kiralama bulunamadı")
    
    if kiralama.durum == "iade_edildi":
        raise HTTPException(status_code=400, detail="Bu kitap zaten iade edilmiş")
    
    kiralama.durum = "iade_edildi"
    kiralama.iade_tarihi = datetime.now()
    db.commit()
    
    return {"message": "Kitap başarıyla iade edildi"}

@app.post("/kitap-iade/{kiralama_id}")
def kullanici_kitap_iade(
    kiralama_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Kullanıcının kendi kiraladığı kitabı iade etmesi"""
    kiralama = db.query(KiralamaModel).filter(
        KiralamaModel.id == kiralama_id,
        KiralamaModel.kullanici_id == current_user.id
    ).first()
    
    if not kiralama:
        raise HTTPException(status_code=404, detail="Kiralama bulunamadı")
    
    if kiralama.durum == "iade_edildi":
        raise HTTPException(status_code=400, detail="Bu kitap zaten iade edilmiş")
    
    kiralama.durum = "iade_edildi"
    kiralama.iade_tarihi = datetime.now()
    db.commit()
    
    return {"message": "Kitabınız başarıyla iade edildi"}

@app.get("/kategoriler/", response_model=List[KategoriResponse])
def aktif_kategorileri_getir(db: Session = Depends(get_db)):
    """Aktif kategorileri getir (Tüm kullanıcılar)"""
    return get_active_categories(db)

@app.post("/setup-admin/")
def setup_admin(db: Session = Depends(get_db)):
    """İlk admin kullanıcısını ve kategorileri oluştur"""
    # Admin kullanıcısı var mı kontrol et
    admin_exists = db.query(UserModel).filter(UserModel.is_admin == True).first()
    if admin_exists:
        raise HTTPException(status_code=400, detail="Admin kullanıcısı zaten mevcut")
    
    # Admin kullanıcısı oluştur
    admin_password = get_password_hash("admin123")
    admin_user = UserModel(
        username="admin",
        email="admin@kutuphane.com",
        hashed_password=admin_password,
        is_admin=True,
        ad="Admin",
        soyad="Kullanıcı"
    )
    db.add(admin_user)
    
    # Varsayılan kategoriler oluştur
    default_categories = [
        {"ad": "Roman", "aciklama": "Roman türündeki kitaplar"},
        {"ad": "Bilim Kurgu", "aciklama": "Bilim kurgu kitapları"},
        {"ad": "Tarih", "aciklama": "Tarih kitapları"},
        {"ad": "Bilim", "aciklama": "Bilim kitapları"},
        {"ad": "Çocuk", "aciklama": "Çocuk kitapları"},
        {"ad": "Eğitim", "aciklama": "Eğitim kitapları"},
        {"ad": "Teknoloji", "aciklama": "Teknoloji kitapları"}
    ]
    
    for cat_data in default_categories:
        kategori = KategoriModel(**cat_data)
        db.add(kategori)
    
    db.commit()
    return {
        "mesaj": "Admin kullanıcısı ve kategoriler oluşturuldu",
        "admin_username": "admin",
        "admin_password": "admin123"
    }

# Kitap işlemleri
@app.get("/kitaplar/", response_model=List[Kitap])
def kitaplari_listele(db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    """Kitapları listele - Kiralama durumu ile birlikte"""
    kitaplar = db.query(KitapModel).all()
    result = []
    
    for kitap in kitaplar:
        # Kitabın kiralama durumunu kontrol et
        aktif_kiralama = db.query(KiralamaModel).filter(
            KiralamaModel.kitap_id == kitap.id,
            KiralamaModel.durum == "kiralandi"
        ).first()
        
        kitap_dict = {
            "id": kitap.id,
            "baslik": kitap.baslik,
            "yazar": kitap.yazar,
            "yayin_yili": kitap.yayin_yili,
            "sayfa_sayisi": kitap.sayfa_sayisi,
            "tur": kitap.tur,
            "kategori": kitap.kategori,
            "isbn": kitap.isbn,
            "aciklama": kitap.aciklama,
            "stok_adedi": kitap.stok_adedi,
            "kiralanabilir": kitap.kiralanabilir,
            "favori": kitap.favori,
            "kiralanmis": aktif_kiralama is not None
        }
        result.append(Kitap(**kitap_dict))
    
    return result

@app.get("/kitap/{kitap_id}", response_model=Kitap)
def kitap_getir(kitap_id: int, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    """Tek bir kitabı getir"""
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Kitap bulunamadı")
    
    # Kitabın kiralama durumunu kontrol et
    aktif_kiralama = db.query(KiralamaModel).filter(
        KiralamaModel.kitap_id == kitap.id,
        KiralamaModel.durum == "kiralandi"
    ).first()
    
    kitap_dict = {
        "id": kitap.id,
        "baslik": kitap.baslik,
        "yazar": kitap.yazar,
        "yayin_yili": kitap.yayin_yili,
        "sayfa_sayisi": kitap.sayfa_sayisi,
        "tur": kitap.tur,
        "kategori": kitap.kategori,
        "isbn": kitap.isbn,
        "aciklama": kitap.aciklama,
        "stok_adedi": kitap.stok_adedi,
        "kiralanabilir": kitap.kiralanabilir,
        "favori": kitap.favori,
        "kiralanmis": aktif_kiralama is not None
    }
    
    return Kitap(**kitap_dict)

@app.get("/kitaplar/musait/", response_model=List[Kitap])
def musait_kitaplari_getir(db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    """Müsait kitapları getir"""
    kitaplar = db.query(KitapModel).filter(KitapModel.kiralanabilir == True).all()
    result = []
    
    for kitap in kitaplar:
        # Kitabın kiralama durumunu kontrol et
        aktif_kiralama = db.query(KiralamaModel).filter(
            KiralamaModel.kitap_id == kitap.id,
            KiralamaModel.durum == "kiralandi"
        ).first()
        
        if not aktif_kiralama:  # Sadece müsait olanları ekle
            kitap_dict = {
                "id": kitap.id,
                "baslik": kitap.baslik,
                "yazar": kitap.yazar,
                "yayin_yili": kitap.yayin_yili,
                "sayfa_sayisi": kitap.sayfa_sayisi,
                "tur": kitap.tur,
                "kategori": kitap.kategori,
                "isbn": kitap.isbn,
                "aciklama": kitap.aciklama,
                "stok_adedi": kitap.stok_adedi,
                "kiralanabilir": kitap.kiralanabilir,
                "favori": kitap.favori,
                "kiralanmis": False
            }
            result.append(Kitap(**kitap_dict))
    
    return result

@app.post("/kitap-kirala/", response_model=KiralamaResponse)
def kitap_kirala(
    kiralama_data: KiralamaCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Kitap kirala"""
    # Kitap var mı kontrol et
    kitap = db.query(KitapModel).filter(KitapModel.id == kiralama_data.kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Kitap bulunamadı")
    
    # Kitap kiralanabilir mi?
    if not kitap.kiralanabilir:
        raise HTTPException(status_code=400, detail="Bu kitap kiralanamaz")
    
    # Kitap zaten kiralanmış mı?
    aktif_kiralama = db.query(KiralamaModel).filter(
        KiralamaModel.kitap_id == kiralama_data.kitap_id,
        KiralamaModel.durum == "kiralandi"
    ).first()
    
    if aktif_kiralama:
        raise HTTPException(status_code=400, detail="Bu kitap zaten kiralanmış")
    
    # Kiralama oluştur
    yeni_kiralama = KiralamaModel(
        kitap_id=kiralama_data.kitap_id,
        kullanici_id=current_user.id,
        beklenen_iade_tarihi=kiralama_data.beklenen_iade_tarihi,
        notlar=kiralama_data.notlar
    )
    
    db.add(yeni_kiralama)
    db.commit()
    db.refresh(yeni_kiralama)
    
    return KiralamaResponse(
        id=yeni_kiralama.id,
        kitap_id=yeni_kiralama.kitap_id,
        kullanici_id=yeni_kiralama.kullanici_id,
        kiralama_tarihi=yeni_kiralama.kiralama_tarihi,
        iade_tarihi=yeni_kiralama.iade_tarihi,
        beklenen_iade_tarihi=yeni_kiralama.beklenen_iade_tarihi,
        durum=yeni_kiralama.durum,
        notlar=yeni_kiralama.notlar,
        kitap_baslik=kitap.baslik,
        kullanici_username=current_user.username
    )

@app.get("/kiraladigim-kitaplar/", response_model=List[KiralamaResponse])
def kiraladigim_kitaplar(
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Kullanıcının kiraladığı kitapları getir"""
    kiralamalar = db.query(KiralamaModel).filter(
        KiralamaModel.kullanici_id == current_user.id
    ).all()
    
    result = []
    for kiralama in kiralamalar:
        result.append(KiralamaResponse(
            id=kiralama.id,
            kitap_id=kiralama.kitap_id,
            kullanici_id=kiralama.kullanici_id,
            kiralama_tarihi=kiralama.kiralama_tarihi,
            iade_tarihi=kiralama.iade_tarihi,
            beklenen_iade_tarihi=kiralama.beklenen_iade_tarihi,
            durum=kiralama.durum,
            notlar=kiralama.notlar,
            kitap_baslik=kiralama.kitap.baslik,
            kullanici_username=kiralama.kullanici.username
        ))
    return result

# Admin kitap yönetimi
@app.post("/admin/kitap-ekle/", response_model=Kitap)
def admin_kitap_ekle(
    kitap: KitapEkle,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Kitap ekle (Admin)"""
    check_admin_permission(current_user)
    
    try:
        kitap.validate(db)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Validasyon hatası: {str(e)}")

    try:
        yeni_kitap = KitapModel(**kitap.dict())
        db.add(yeni_kitap)
        db.commit()
        db.refresh(yeni_kitap)
        
        return Kitap(
            id=yeni_kitap.id,
            baslik=yeni_kitap.baslik,
            yazar=yeni_kitap.yazar,
            yayin_yili=yeni_kitap.yayin_yili,
            sayfa_sayisi=yeni_kitap.sayfa_sayisi,
            tur=yeni_kitap.tur,
            kategori=yeni_kitap.kategori,

            aciklama=yeni_kitap.aciklama,
            stok_adedi=yeni_kitap.stok_adedi,
            kiralanabilir=yeni_kitap.kiralanabilir,
            favori=yeni_kitap.favori,
            kiralanmis=False
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Kitap eklenirken hata oluştu: {str(e)}")

@app.put("/admin/kitap-guncelle/{kitap_id}", response_model=Kitap)
def admin_kitap_guncelle(
    kitap_id: int,
    guncel_kitap: KitapEkle,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Kitap güncelle (Admin)"""
    check_admin_permission(current_user)
    
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Güncellenecek kitap bulunamadı.")
    
    try:
        guncel_kitap.validate(db)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    for field, value in guncel_kitap.dict().items():
        setattr(kitap, field, value)

    db.commit()
    db.refresh(kitap)
    
    return Kitap(
        id=kitap.id,
        baslik=kitap.baslik,
        yazar=kitap.yazar,
        yayin_yili=kitap.yayin_yili,
        sayfa_sayisi=kitap.sayfa_sayisi,
        tur=kitap.tur,
        kategori=kitap.kategori,
        
        aciklama=kitap.aciklama,
        stok_adedi=kitap.stok_adedi,
        kiralanabilir=kitap.kiralanabilir,
        favori=kitap.favori,
        kiralanmis=False
    )

@app.delete("/admin/kitap-sil/{kitap_id}")
def admin_kitap_sil(
    kitap_id: int,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user)
):
    """Kitap sil (Admin)"""
    check_admin_permission(current_user)
    
    kitap = db.query(KitapModel).filter(KitapModel.id == kitap_id).first()
    if not kitap:
        raise HTTPException(status_code=404, detail="Kitap bulunamadı")
    
    # Kitap kiralanmış mı kontrol et
    aktif_kiralama = db.query(KiralamaModel).filter(
        KiralamaModel.kitap_id == kitap_id,
        KiralamaModel.durum == "kiralandi"
    ).first()
    
    if aktif_kiralama:
        raise HTTPException(status_code=400, detail="Bu kitap kiralanmış durumda, silinemez")
    
    db.delete(kitap)
    db.commit()
    return {"mesaj": f"'{kitap.baslik}' kitabı silindi"}

# Favori işlemleri
@app.get("/kitaplar/favoriler/", response_model=List[Kitap])
def favori_kitaplari_getir(db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    return db.query(KitapModel).filter(KitapModel.favori == True).all()

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
