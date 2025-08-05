from sqlalchemy import Column, Integer, String, Boolean
from database import Base

class KitapModel(Base):
    __tablename__ = "kitaplar"

    id = Column(Integer, primary_key=True, index=True)
    baslik = Column(String, index=True)
    yazar = Column(String)
    yayin_yili = Column(Integer)
    sayfa_sayisi = Column(Integer)
    tur = Column(String, default="Bilinmiyor")
    favori = Column(Boolean, default=False)
