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

// 🔒 Protection anti-scraper : vérifie l'agent utilisateur
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$botList = ['httrack', 'wget', 'curl', 'python', 'fetch', 'httpclient', 'libwww'];

foreach ($botList as $bot) {
    if (stripos($userAgent, $bot) !== false) {
        logDeniedAccess("Bot détecté : $userAgent");
        denyAccess("Accès refusé aux bots");
    }
}

// 🔒 Vérifie le Referer exact
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

