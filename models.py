from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import Base

class KitapModel(Base):
    __tablename__ = "kitaplar"

    id = Column(Integer, primary_key=True, index=True)
    baslik = Column(String, nullable=False)
    yazar = Column(String, nullable=False)
    yayin_yili = Column(Integer, nullable=False)
    sayfa_sayisi = Column(Integer, nullable=False)
    tur = Column(String, nullable=True)
    kategori = Column(String, nullable=False)
    isbn = Column(String, unique=True, nullable=True)  # ISBN numarası
    aciklama = Column(Text, nullable=True)  # Kitap açıklaması
    stok_adedi = Column(Integer, default=1)  # Stok adedi
    kiralanabilir = Column(Boolean, default=True)  # Kiralanabilir mi?
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)  # Admin yetkisi
    ad = Column(String, nullable=True)  # Kullanıcı adı
    soyad = Column(String, nullable=True)  # Kullanıcı soyadı
    telefon = Column(String, nullable=True)  # Telefon numarası
    adres = Column(Text, nullable=True)  # Adres
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class KategoriModel(Base):
    __tablename__ = "kategoriler"

    id = Column(Integer, primary_key=True, index=True)
    ad = Column(String, unique=True, nullable=False)
    aciklama = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class KiralamaModel(Base):
    __tablename__ = "kiralamalar"

    id = Column(Integer, primary_key=True, index=True)
    kitap_id = Column(Integer, ForeignKey("kitaplar.id"), nullable=False)
    kullanici_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    kiralama_tarihi = Column(DateTime(timezone=True), server_default=func.now())
    iade_tarihi = Column(DateTime(timezone=True), nullable=True)
    beklenen_iade_tarihi = Column(DateTime(timezone=True), nullable=False)
    durum = Column(String, default="kiralandi")  # kiralandi, iade_edildi, gecikti
    notlar = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # İlişkiler
    kitap = relationship("KitapModel", backref="kiralamalar")
    kullanici = relationship("UserModel", backref="kiralamalar")

class FavoriModel(Base):
    __tablename__ = "favoriler"

    id = Column(Integer, primary_key=True, index=True)
    kullanici_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    kitap_id = Column(Integer, ForeignKey("kitaplar.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # İlişkiler
    kullanici = relationship("UserModel", backref="favoriler")
    kitap = relationship("KitapModel", backref="favoriler")
