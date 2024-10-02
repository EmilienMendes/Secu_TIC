10 a. DIGITAL SIGNATURE ALGORITHM
b. gendsa permet de generer la clé privée, dsaparam permet de ma,ipuler ou generer des parametres DSA. openssl-dsa Manipulation de clé dsa.
Selection avec dsaparam. On genere la privée avec gendsa.  On extrait la clé publique avec openssl-dsa

  c. openssl dsaparam -out dsa.pem 1024
    openssl gendsa -out private.pem dsa.pem
    openssl dsa -in private.pem -outform PEM -pubout -out public.pem

d. Chiffrer la clé ! Les nombres correspondent au nombre de bit de sécurité.

    e. openssl dgst -sha256 -sign key.pem message.txt > message.txt.sig
    Avec cette commmande on signe le fichier
    
sha256 est l'algorithme de hash, la clé est la clé privée de signature et on signe message.txt et le signé est message.txt.sig

 ON peut verifier la signature avec openssl dgst -sha256 -verify public-key.pem -signature message.txt.sig message.txt
    sha256 est le meme algo de hash, on verifie avec le clé publique public key et on precise le fichier signé et le fichier ce qui permet de verifier.
    
DSA n'est pas fait pour le chiffrement, on genere des signature et la clé publique permet de verifier, c'est tout. RSA permet de chiffrer.
