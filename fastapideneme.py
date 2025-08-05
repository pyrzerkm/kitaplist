from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI()

# Kullanıcıdan sadece bu alanlar istenecek:
class KitapEkle(BaseModel):
    baslik: str
    yazar: str
    yayin_yili: int
    sayfa_sayisi: int
    tur: Optional[str] = "Bilinmiyor"

# Dönüşte kullanılacak tam model (ID ve favori ekli):
class Kitap(KitapEkle):
    id: int
    favori: bool = False

kutuphane: List[Kitap] = []
id_sayaci = 1

@app.get("/")
def anasayfa():
    return {"mesaj": "📚 Kitap API'ye hoş geldin!"}

@app.get("/kitaplar/", response_model=List[Kitap])
def kitaplari_listele():
    return kutuphane

@app.get("/kitaplar/favoriler/", response_model=List[Kitap])
def favori_kitaplari_getir():
    return [k for k in kutuphane if k.favori]

@app.post("/kitap-ekle/", response_model=Kitap)
def kitap_ekle(kitap: KitapEkle):
    global id_sayaci
    yeni_kitap = Kitap(id=id_sayaci, favori=False, **kitap.dict())
    kutuphane.append(yeni_kitap)
    id_sayaci += 1
    return yeni_kitap

@app.get("/kitap/{kitap_id}", response_model=Kitap)
def kitap_getir(kitap_id: int):
    for kitap in kutuphane:
        if kitap.id == kitap_id:
            return kitap
    raise HTTPException(status_code=404, detail="Kitap bulunamadı!")

@app.delete("/kitap-sil/{kitap_id}")
def kitap_sil(kitap_id: int):
    global kutuphane
    yeni_liste = [k for k in kutuphane if k.id != kitap_id]
    if len(yeni_liste) == len(kutuphane):
        raise HTTPException(status_code=404, detail="Kitap silinemedi, ID bulunamadı.")
    kutuphane = yeni_liste
    return {"mesaj": f"{kitap_id} numaralı kitap silindi."}

@app.put("/kitap-guncelle/{kitap_id}", response_model=Kitap)
def kitap_guncelle(kitap_id: int, guncel_kitap: KitapEkle):
    for index, kitap in enumerate(kutuphane):
        if kitap.id == kitap_id:
            yeni_kitap = Kitap(id=kitap_id, favori=kitap.favori, **guncel_kitap.dict())
            kutuphane[index] = yeni_kitap
            return yeni_kitap
    raise HTTPException(status_code=404, detail="Güncellenecek kitap bulunamadı.")

@app.post("/kitap/{kitap_id}/favori/")
def favori_yap(kitap_id: int):
    for kitap in kutuphane:
        if kitap.id == kitap_id:
            if kitap.favori:
                return {"mesaj": f"{kitap.baslik} zaten favorilerdeydi."}
            kitap.favori = True
            return {"mesaj": f"{kitap.baslik} favorilere eklendi."}
    raise HTTPException(status_code=404, detail="Kitap bulunamadı!")

@app.post("/kitap/{kitap_id}/favori-kaldir/")
def favori_kaldir(kitap_id: int):
    for kitap in kutuphane:
        if kitap.id == kitap_id:
            if not kitap.favori:
                return {"mesaj": f"{kitap.baslik} zaten favorilerden çıkarılmıştı."}
            kitap.favori = False
            return {"mesaj": f"{kitap.baslik} favorilerden çıkarıldı."}
    raise HTTPException(status_code=404, detail="Kitap bulunamadı!")
