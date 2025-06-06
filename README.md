# Secure-PHP-File-Router

Secure static file access in PHP — protect CSS, JS, images, fonts, etc. via referer validation, anti-bot filtering, and full access logging. No .htaccess needed.


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

Un développeur passionné par la sécurité des ressources web.

MIT License

Copyright (c) 2025 Yuko90

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all  
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  
SOFTWARE.



