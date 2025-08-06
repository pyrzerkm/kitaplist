from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from database import Base

class KitapModel(Base):
    __tablename__ = "kitaplar"

    id = Column(Integer, primary_key=True, index=True)
    baslik = Column(String, nullable=False)
    yazar = Column(String, nullable=False)
    yayin_yili = Column(Integer, nullable=False)
    sayfa_sayisi = Column(Integer, nullable=False)
    tur = Column(String, nullable=True)
    favori = Column(Boolean, default=False)
    kategori = Column(String, nullable=False)

class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
