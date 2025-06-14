Si ce projet vous a aidé, pensez à lui laisser une étoile (⭐) en haut à droite

> SecurePHPFileRouter est un micro-routeur PHP sécurisé pour protéger vos fichiers statiques (CSS, JS, images, etc.).  
> Il bloque les bots comme HTTrack/Wget, vérifie les Referer, empêche les accès directs et journalise les tentatives.  
> Aucun `.htaccess`, aucune dépendance — 100% PHP, prêt à l’emploi.
> 
> Vous pouvez également l’adapter pour qu’il devienne le routeur principal, en renommant secure.php en index.php, puis en ajoutant une redirection automatique vers, par exemple, index2.php lorsque aucun fichier n’est spécifié.

session_start(); mettre derrières

if (empty($_GET['file'])) {
    header("Location: index2.php");
    exit;
}

Par exemple, le système de détection anti-bot s’active automatiquement.


[![YouTube Demo](https://img.shields.io/badge/Demo-YouTube-red?logo=youtube)](https://youtu.be/UOnUyu8pFmM)



Fonctionnalités
✅ Protection d’un dossier complet (ex : /source/)

✅ Accès aux fichiers uniquement via secure.php

✅ Filtrage strict du Referer pour éviter les appels externes

✅ Détection des bots par User-Agent (HTTrack, wget, curl…)

✅ Journalisation des accès refusés (/logs/access_denied.log)

✅ Blocage des chemins suspects (../, \)

✅ Entièrement en PHP — sans .htaccess, ni framework


/mon-projet/

├── index.php

├── secure.php

├── /source/

│   ├── css/style.css

│   ├── js/app.js

│   ├── img/logo.png

│   └── fonts/font.woff2

└── /logs/

    └── access_denied.log
exemple

<link rel="stylesheet" href="secure.php?file=css/style.css">


<script src="secure.php?file=js/app.js"></script>



Journalisation (logs/access_denied.log)
Chaque tentative refusée est enregistrée avec :

IP

Date

Motif

Agent utilisateur

Exemple de ligne :

[IP][2025-06-06 18:24:11] Bot détecté : Mozilla/4.5 (compatible; HTTrack 3.0x; Windows XP)

 Options d’extension possibles
 Authentification par session

 Jetons d'accès temporaires

 Liste blanche IP

 Interface d’admin pour lire les logs




