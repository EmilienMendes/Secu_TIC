#!/usr/bin/python3
from bottle import route, run, template, request, response
from PIL import Image
from my_qrcode import * 
from steganographie import * 
import subprocess,base64,os


def supprimer_fichier(liste_fichier) :
    for fichier in liste_fichier :
        os.remove(fichier)

# On extrait la partie qrcode de l'image
def extraire_image(nom_fichier_qr_code,nom_fichier_attestation) :
    attestation = Image.open(nom_fichier_attestation)
    qrImage = attestation.crop((1468,984,1468+110,984+110))
    qrImage.save(nom_fichier_qr_code, "PNG")
    attestation.close()

# Creation de l'image avec le qr code
def creation_image(bloc_information,identite,nom_fichier) :
    nom_fichier_qr_code = "qrcode.png"
    # Signature du bloc d'information avec la cle du serveur
    sortie = subprocess.run("echo -n  '%s' | openssl dgst -sha256 -sign certificat/AC/ecc.serveur.key.pem -binary "%bloc_information,shell=True,stdout=subprocess.PIPE)
    # Conversion sous format ASCII
    creer_qr_code(nom_fichier_qr_code, base64.b64encode(sortie.stdout))
    # Creation de l'image avec le texte le qr code et le fond
    subprocess.run("./script/creer_image %s %s %s"%(identite,nom_fichier_qr_code,nom_fichier),shell=True)
    supprimer_fichier([nom_fichier_qr_code])


def certification_horodatage(image) :
    # Creation de la certification https://freetsa.org 
    subprocess.run("openssl ts -query -data %s -no_nonce -sha512 -cert -out certificat/horodatage/file.tsq "%image,shell=True)
    subprocess.run("curl -H \"Content-Type: application/timestamp-query\" --data-binary '@certificat/horodatage/file.tsq' https://freetsa.org/tsr > certificat/horodatage/file.tsr",stdout=subprocess.PIPE,shell=True)

    # Sauvegarde du contenu de la certification sous format binaire
    with open("certificat/horodatage/file.tsq","rb") as f :
        contenu_horodatage = f.read()
    
    supprimer_fichier(["certificat/horodatage/file.tsq","certificat/horodatage/file.tsr"])
    return contenu_horodatage


def verification_horodatage(fichier_tsq) : 
    # Verification a partir du fichier tsq avec les certificats disponible sur freetsa
    subprocess.run("curl -H \"Content-Type: application/timestamp-query\" --data-binary '@%s' https://freetsa.org/tsr > certificat/horodatage/file.tsr"%fichier_tsq,shell=True)
    sortie = subprocess.run("openssl ts -verify -in certificat/horodatage/file.tsr -queryfile %s -CAfile certificat/horodatage/cacert.pem -untrusted certificat/horodatage/tsa.crt"%fichier_tsq,shell=True,stdout=subprocess.PIPE)

    return sortie.stdout

# Conversion de toutes les donnees en format binaire (bloc information et horodatage)
def conversion_binaire(identite,intitule_certification,horodatage) :
    
    contenu_stegano = []
    message_vers_binaire(contenu_stegano,identite)
    message_vers_binaire(contenu_stegano,intitule_certification)
    
    # On ajoute des octets de 0 pour avoir 64 caractères
    for caractere_additionnel in range ((64 - (len(identite) + len(intitule_certification) ))) :
        contenu_stegano.append('0'* 8)

    # https://stackoverflow.com/questions/1395356/how-can-i-make-bin30-return-00011110-instead-of-0b11110
    for byte in horodatage:
        contenu_stegano.append(bin(byte)[2:].zfill(8))

    contenu_stegano = ''.join([c for c in contenu_stegano])

    return contenu_stegano


@route('/creation', method='POST')
def création_attestation():
    # Recupération des données fournis par curl
    contenu_identité = request.forms.get('identite')
    contenu_intitulé_certification = request.forms.get('intitule_certif')

    print('nom prénom :', contenu_identité, ' intitulé de la certification :',contenu_intitulé_certification)
    if(len(contenu_identité) + len(contenu_intitulé_certification ) > 64 ) :
        return "Nom et identite ne peux pas dépasse 64 caractères !!"
    
    # Creation de l'image
    nom_image = "attestation.png"
    creation_image(contenu_identité+contenu_intitulé_certification,contenu_identité,nom_image)

    # Horodatage de l'image
    mon_image = Image.open(nom_image)
    horodatage = certification_horodatage(nom_image)

    # Stéganographie du bloc d'information et de l'horodatage
    bloc_information = conversion_binaire(contenu_identité,contenu_intitulé_certification,horodatage)
    cacher(mon_image,bloc_information)
    # On sauvegarde l'image pour pouvoir la renvoyer aprè
    mon_image.save(nom_image,overwrite=True)
    mon_image.close()

    response.set_header('Content-type', 'text/plain')
    
    return "ok!\n"


@route('/verification', method='POST')
def vérification_attestation():
    nom_fichier_verifier = 'attestation_a_verifier.png'
    nom_fichier_qr_code = "qrcoderecupere.png"
    nom_verification_signature = "sigature"

    nom_fichier_timestamp = "certificat/horodatage/file.tsq"
    nom_fichier_requete_timestamp = "certificat/horodatage/file.tsr"
    # La taille du timestamp est constante 91 octets
    taille_timestamp = 91

    # On sauvegarde l'image recu par curl dans un fichier temporaire
    contenu_image = request.files.get('image')
    contenu_image.save(nom_fichier_verifier,overwrite=True)

    img_stegano = Image.open(nom_fichier_verifier)

    # Recuperation des données cachés par stéganographie
    longueur_message_recuperer = (64 + taille_timestamp) 
    message_recuperer = recuperer(img_stegano,longueur_message_recuperer)
    img_stegano.close()

    # Récupération des 64 premiers caractères
    contenu_bloc = ""
    for i in range(64) :
        car = message_recuperer[8*i:(i+1)*8]
        if(int(car,2) > 0) :
            contenu_bloc += chr(int(car, 2)) 
    print(contenu_bloc)

    # Extraction des données du qrcode
    extraire_image(nom_fichier_qr_code,nom_fichier_verifier)
    donnes_qr_code = lire_qr_code(nom_fichier_qr_code)
    with open(nom_verification_signature,"wb") as f :
        f.write(base64.b64decode(donnes_qr_code[0]))

    certificat_correct = False 
    # Verification de la correspondance entres les données signés avec la clé privé et les données trouvés 
    sortie = subprocess.run("echo -n '%s' | openssl dgst -sha256 -verify certificat/AC/ecc.serveur.pub.pem -signature %s -binary"%(contenu_bloc,nom_verification_signature),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if(b"OK" in sortie.stdout) :
        # Récupération des données binaire du fichier tsq 
        with open(nom_fichier_timestamp,"wb") as f :
            for i in range(64,taille_timestamp+64) :
                f.write(bytes([int(message_recuperer[i*8:(i+1)*8],2)]))

        verification = verification_horodatage(nom_fichier_timestamp).decode()
        if("OK" in verification) :
            certificat_correct = True

    supprimer_fichier([nom_fichier_qr_code,nom_fichier_verifier,nom_fichier_timestamp,nom_fichier_requete_timestamp,nom_verification_signature])

    # Envoi de la reponse a l'utilisateur sur l'authencitié du certificat
    response.set_header('Content-type', 'text/plain')
    if certificat_correct :
        return "Certification correct!\n"
    return "Certification erroné!\n"

# Envoi de l'attestation
@route('/attestation')
def récupérer_fond():
    response.set_header('Content-type', 'image/png')
    descripteur_fichier = open('attestation.png','rb')
    supprimer_fichier(['attestation.png'])
    contenu_fichier = descripteur_fichier.read()
    descripteur_fichier.close()
    return contenu_fichier

run(host='0.0.0.0',port=8080,debug=True)

