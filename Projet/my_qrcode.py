#!/usr/bin/python3
import qrcode
import zbarlight
from PIL import Image

def creer_qr_code(nom_fichier,data) :
    qr = qrcode.make(data)
    qr.save(nom_fichier, scale=2)



def lire_qr_code(nom_fichier) :
    image = Image.open(nom_fichier)
    data = zbarlight.scan_codes(['qrcode'], image)
    return data
