<?php
/**
 * Rescate de Plan B Conector.
 * Restaura un punto de restauración SIN cargar WordPress, para poder recuperar la web
 * aunque un plugin o una actualización la haya dejado sin arrancar.
 * Solo responde a peticiones firmadas por el Panel Plan B.
 * Compatible con PHP 5.6 a 8.5.
 */
@set_time_limit(900);
@ignore_user_abort(true);
header('Content-Type: application/json; charset=utf-8');
header('X-Robots-Tag: noindex');

function rescate_salir($code, $datos)
{
    if (function_exists('http_response_code')) http_response_code($code);
    echo json_encode($datos);
    exit;
}

$contenido = realpath(__DIR__ . '/../..');               // …/wp-content
$raiz = dirname($contenido);                              // …/ (ABSPATH)
$puntos = $contenido . '/planb-puntos';
if (!is_file($puntos . '/clave.php')) rescate_salir(503, array('error' => 'sin clave'));
$secreto = (string)include $puntos . '/clave.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') rescate_salir(405, array('error' => 'metodo'));
$cuerpo = (string)file_get_contents('php://input');
$t = isset($_SERVER['HTTP_X_PLANB_TIEMPO']) ? (string)$_SERVER['HTTP_X_PLANB_TIEMPO'] : '';
$nonce = isset($_SERVER['HTTP_X_PLANB_NONCE']) ? (string)$_SERVER['HTTP_X_PLANB_NONCE'] : '';
$firma = isset($_SERVER['HTTP_X_PLANB_FIRMA']) ? (string)$_SERVER['HTTP_X_PLANB_FIRMA'] : '';
if ($secreto === '' || $t === '' || strlen($nonce) < 16 || abs(time() - (int)$t) > 300) rescate_salir(401, array('error' => 'firma'));
$esperada = hash_hmac('sha256', $t . '|' . $nonce . '|POST|/rescate|' . $cuerpo, $secreto);
if (!hash_equals($esperada, $firma)) rescate_salir(401, array('error' => 'firma'));
// Una firma no se puede reutilizar
$usados = $puntos . '/nonces.php';
$lista = is_file($usados) ? (array)include $usados : array();
foreach ($lista as $k => $v) if ($v < time() - 900) unset($lista[$k]);
if (isset($lista[$nonce])) rescate_salir(401, array('error' => 'repetida'));
$lista[$nonce] = time();
@file_put_contents($usados, '<?php return ' . var_export($lista, true) . ';');

$datos = json_decode($cuerpo, true);

/*
 * 1.7.37 · «Levantar web» (Jesús, 26/11/2026): cosas que se pueden hacer aunque WordPress no arranque.
 *   mirar               → modo mantenimiento atascado, último error grave de PHP (qué plugin o tema), plugins cambiados hace poco
 *   quitar-mantenimiento → borra el .maintenance que dejó una actualización cortada
 *   apagar-plugin       → aparta la carpeta del plugin (se renombra, no se borra) para que WordPress no lo cargue
 *   encender-plugin     → la devuelve a su sitio
 * Sin «accion», restaura un punto (como siempre).
 */
$accion = isset($datos['accion']) ? (string)$datos['accion'] : '';
if ($accion !== '') {
    $plug = $contenido . '/plugins';
    if ($accion === 'mirar') {
        $m = $raiz . '/.maintenance';
        $fatal = null;
        foreach (array($contenido . '/debug.log', $raiz . '/error_log', dirname($raiz) . '/logs/error_log', $raiz . '/php_errorlog') as $lf) {
            if (!is_file($lf) || !is_readable($lf)) continue;
            $tam = (int)@filesize($lf);
            $fh = @fopen($lf, 'rb'); if (!$fh) continue;
            if ($tam > 262144) @fseek($fh, $tam - 262144);
            $txt = (string)@stream_get_contents($fh); @fclose($fh);
            if (!preg_match_all('/^.*PHP Fatal error.*$/m', $txt, $mm)) continue;
            $l = end($mm[0]);
            $cuando = preg_match('/^\[([^\]]+)\]/', $l, $c) ? strtotime(preg_replace('/\s+[A-Za-z\/_]+$/', '', $c[1])) : @filemtime($lf);
            if ($fatal && $fatal['cuando'] >= $cuando) continue;
            $p = preg_match('#/wp-content/plugins/([A-Za-z0-9._-]+)/#', $l, $x) ? $x[1] : null;
            $t = preg_match('#/wp-content/themes/([A-Za-z0-9._-]+)/#', $l, $x) ? $x[1] : null;
            // Solo lo justo: ni rutas del servidor ni datos; el mensaje recortado
            $msg = preg_replace('#(/[^\s:]*)?/wp-content/#', 'wp-content/', preg_replace('/^\[[^\]]+\]\s*/', '', $l));
            $fatal = array('cuando' => (int)$cuando, 'plugin' => $p, 'tema' => $t, 'mensaje' => substr($msg, 0, 220), 'registro' => basename($lf));
        }
        $recientes = array(); $apagados = array();
        foreach ((array)glob($plug . '/*', GLOB_ONLYDIR) as $d) {
            $b = basename($d);
            if (strpos($b, '.planb-apagado') !== false) { $apagados[] = $b; continue; }
            $mt = (int)@filemtime($d);
            if ($mt > time() - 3 * 86400) $recientes[] = array('slug' => $b, 'cuando' => $mt);
        }
        rescate_salir(200, array('mantenimiento' => is_file($m) ? time() - (int)@filemtime($m) : null, 'fatal' => $fatal, 'recientes' => $recientes, 'apagados' => $apagados, 'ahora' => time()));
    }
    if (!defined('PLANB_RESTAURAR_LIB')) define('PLANB_RESTAURAR_LIB', 1);
    require_once __DIR__ . '/restaurar.php';
    if (!planb_rs_ocupar($puntos, 'rescate-' . $accion)) rescate_salir(409, array('error' => 'ocupada'));
    if ($accion === 'quitar-mantenimiento') {
        $m = $raiz . '/.maintenance';
        rescate_salir(200, array('quitado' => is_file($m) ? @unlink($m) : true));
    }
    $slug = isset($datos['slug']) ? (string)$datos['slug'] : '';
    if (!preg_match('/^[A-Za-z0-9._-]{1,100}$/', $slug) || $slug === 'planb-conector' || strpos($slug, '..') !== false) rescate_salir(400, array('error' => 'slug'));
    if ($accion === 'apagar-plugin') {
        if (!is_dir($plug . '/' . $slug)) rescate_salir(404, array('error' => 'no está'));
        $dest = $plug . '/' . $slug . '.planb-apagado';
        if (file_exists($dest)) $dest .= '-' . time();
        rescate_salir(200, array('apagado' => @rename($plug . '/' . $slug, $dest), 'como' => basename($dest)));
    }
    if ($accion === 'encender-plugin') {
        $de = null;
        foreach ((array)glob($plug . '/' . $slug . '.planb-apagado*', GLOB_ONLYDIR) as $d) $de = $d;
        if (!$de || is_dir($plug . '/' . $slug)) rescate_salir(404, array('error' => 'no está apagado'));
        rescate_salir(200, array('encendido' => @rename($de, $plug . '/' . $slug)));
    }
    rescate_salir(400, array('error' => 'accion'));
}

$id = isset($datos['punto']) ? preg_replace('/[^0-9a-z-]/', '', (string)$datos['punto']) : '';
$dir = $puntos . '/' . $id;
if ($id === '' || !is_file($dir . '/archivos.zip') || !is_file($dir . '/bd.sql')) rescate_salir(404, array('error' => 'punto no encontrado'));
if (!class_exists('ZipArchive')) rescate_salir(500, array('error' => 'sin ZipArchive'));

// 1.7.37: restauración segura (restaurar.php) y un solo trabajo a la vez
if (!defined('PLANB_RESTAURAR_LIB')) define('PLANB_RESTAURAR_LIB', 1);
if (!is_file(__DIR__ . '/restaurar.php')) rescate_salir(500, array('error' => 'falta restaurar.php'));
require_once __DIR__ . '/restaurar.php';
if (!planb_rs_ocupar($puntos, 'rescate')) {
    $o = planb_rs_ocupado_info($puntos);
    rescate_salir(409, array('error' => 'ocupada', 'que' => $o ? $o['que'] : '?', 'desde' => $o ? $o['desde'] : 0));
}
// Primero se extrae el zip aparte: si falla, no se ha tocado nada
$prep = planb_rs_preparar($dir);
if (empty($prep['ok'])) rescate_salir(500, array('error' => 'No se restaura: ' . $prep['error']));

/* 1) Base de datos, con los datos de wp-config.php */
$cfgf = is_file($raiz . '/wp-config.php') ? $raiz . '/wp-config.php' : dirname($raiz) . '/wp-config.php';
$cfg = (string)@file_get_contents($cfgf);
$c = array();
foreach (array('DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST') as $k) {
    $c[$k] = preg_match("/define\\(\\s*['\"]" . $k . "['\"]\\s*,\\s*(['\"])(.*?)\\1\\s*\\)/s", $cfg, $m) ? stripcslashes($m[2]) : '';
}
$host = $c['DB_HOST'] ?: 'localhost'; $puerto = null; $sock = null;
if (strpos($host, ':') !== false) { list($host, $extra) = explode(':', $host, 2); if (is_numeric($extra)) $puerto = (int)$extra; else $sock = $extra; }
$db = @new mysqli($host, $c['DB_USER'], $c['DB_PASSWORD'], $c['DB_NAME'], $puerto ? $puerto : 3306, $sock);
if ($db->connect_errno) { planb_rs_borrar($prep['tmp']); rescate_salir(500, array('error' => 'base de datos: ' . $db->connect_error)); }
$db->set_charset('utf8mb4');
$h = fopen($dir . '/bd.sql', 'r');
$buf = ''; $errores = 0; $hechas = 0;
while (($l = fgets($h)) !== false) {
    $buf .= $l;
    if (substr(rtrim($l), -1) === ';') {
        $s = str_replace(array('\\\\', "\\'"), '', $buf);
        if (substr_count($s, "'") % 2 === 0) { $buf = preg_replace('/\{[0-9a-f]{64}\}/', '%', $buf); if (!$db->query($buf)) $errores++; else $hechas++; $buf = ''; }
    }
}
fclose($h);
$db->close();

/* 2) Archivos: cada plugin y tema se cambia por el del punto (los actuales van a una papelera) y el resto encima */
$cambio = planb_rs_cambiar($dir, $prep['tmp'], $raiz, $contenido);
if (function_exists('opcache_reset')) @opcache_reset();
rescate_salir(200, array('restaurado' => !empty($cambio['ok']), 'errores_sql' => $errores, 'sentencias' => $hechas, 'problemas' => $cambio['problemas'], 'seguro' => 1));
