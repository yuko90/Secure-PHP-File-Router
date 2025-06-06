# Secure-PHP-File-Router

Protect static files (CSS, JS, images, fonts...) in PHP using a secure file router with referer validation, MIME filtering, and access logging.

---

## index.php

```html
<link rel="stylesheet" href="secure.php?file=css/style.css">
<link rel="stylesheet" href="secure.php?file=css/1.css">

```css
body {
  background-color: #3c546f;
  color: white;
  font-family: 'MyFont', sans-serif;
}

secure.php

<?php
session_start();

$baseDir = __DIR__ . '/source/';
$logDir  = __DIR__ . '/logs';
$logFile = $logDir . '/access_denied.log';

$file = $_GET['file'] ?? '';
$file = str_replace(['..', '\\'], '', $file);
$ext  = strtolower(pathinfo($file, PATHINFO_EXTENSION));

$mimeTypes = [
    'css'   => 'text/css',
    'js'    => 'application/javascript',
    'png'   => 'image/png',
    'jpg'   => 'image/jpeg',
    'jpeg'  => 'image/jpeg',
    'gif'   => 'image/gif',
    'svg'   => 'image/svg+xml',
    'woff'  => 'font/woff',
    'woff2' => 'font/woff2',
    'ttf'   => 'font/ttf',
    'eot'   => 'application/vnd.ms-fontobject',
    'pdf'   => 'application/pdf',
];

// Validation extension et nom
if (!$file || !isset($mimeTypes[$ext]) || !preg_match('/^[\w\-\/\.]+$/', $file)) {
    denyAccess("Extension ou nom de fichier invalide");
}

// Résolution chemin absolu
$fullPath = realpath($baseDir . $file);
if (!$fullPath || !file_exists($fullPath) || !str_starts_with($fullPath, realpath($baseDir))) {
    denyAccess("Fichier interdit ou introuvable : $file");
}

// Protection anti-scraper : vérifie l'agent utilisateur
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$botList = ['httrack', 'wget', 'curl', 'python', 'fetch', 'httpclient', 'libwww'];

foreach ($botList as $bot) {
    if (stripos($userAgent, $bot) !== false) {
        logDeniedAccess("Bot détecté : $userAgent");
        denyAccess("Accès refusé aux bots");
    }
}

// Vérifie le Referer exact
$referer = $_SERVER['HTTP_REFERER'] ?? '';
$host = $_SERVER['HTTP_HOST'] ?? '';
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$expectedBase = "$scheme://$host";

if (!preg_match('#^' . preg_quote($expectedBase, '#') . '/#', $referer)) {
    logDeniedAccess("Referer invalide ou absent : " . ($referer ?: 'aucun'));
    denyAccess("Referer non autorisé");
}

// En-têtes anti-cache
header("Expires: 0");
header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");

// Type MIME
header("Content-Type: " . $mimeTypes[$ext]);
readfile($fullPath);
exit;

// --- Fonctions ---
function denyAccess(string $msg = 'refusé') {
    header("Content-Type: text/plain");
    echo "/* accès $msg */";
    exit;
}

function logDeniedAccess(string $reason) {
    global $logDir, $logFile;

    if (!is_dir($logDir)) {
        mkdir($logDir, 0777, true);
    }

    $ip = $_SERVER['REMOTE_ADDR'] ?? 'inconnu';
    $date = date('Y-m-d H:i:s');
    $logLine = "[$ip][$date] $reason\n";

    @file_put_contents($logFile, $logLine, FILE_APPEND);
}


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
<img src="secure.php?file=img/logo.png" alt="logo">



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



