from sqlalchemy import Column, Integer, String, Boolean
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
    kategori = Column(String, nullable=False)  # ✅ Yeni alan
