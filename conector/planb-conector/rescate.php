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
$id = isset($datos['punto']) ? preg_replace('/[^0-9a-z-]/', '', (string)$datos['punto']) : '';
$dir = $puntos . '/' . $id;
if ($id === '' || !is_file($dir . '/archivos.zip') || !is_file($dir . '/bd.sql')) rescate_salir(404, array('error' => 'punto no encontrado'));
if (!class_exists('ZipArchive')) rescate_salir(500, array('error' => 'sin ZipArchive'));

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
if ($db->connect_errno) rescate_salir(500, array('error' => 'base de datos: ' . $db->connect_error));
$db->set_charset('utf8mb4');
$h = fopen($dir . '/bd.sql', 'r');
$buf = ''; $errores = 0;
while (($l = fgets($h)) !== false) {
    $buf .= $l;
    if (substr(rtrim($l), -1) === ';') {
        $s = str_replace(array('\\\\', "\\'"), '', $buf);
        if (substr_count($s, "'") % 2 === 0) { $buf = preg_replace('/\{[0-9a-f]{64}\}/', '%', $buf); if (!$db->query($buf)) $errores++; $buf = ''; }
    }
}
fclose($h);
$db->close();

/* 2) Archivos */
function rescate_borrar($d)
{
    if (is_link($d) || is_file($d)) return @unlink($d);
    if (!is_dir($d)) return false;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) { if ($f->isDir() && !$f->isLink()) @rmdir($f->getPathname()); else @unlink($f->getPathname()); }
    return @rmdir($d);
}
$zip = new ZipArchive();
if ($zip->open($dir . '/archivos.zip') !== true) rescate_salir(500, array('error' => 'zip'));
foreach (array('plugins', 'themes') as $carpeta) {
    foreach ((array)glob($contenido . '/' . $carpeta . '/*') as $p) {
        if (basename($p) === 'planb-conector') continue;
        rescate_borrar($p); // se vuelve a extraer tal como estaba
    }
}
$ok = $zip->extractTo($raiz);
$zip->close();
if (function_exists('opcache_reset')) @opcache_reset();
rescate_salir(200, array('restaurado' => $ok, 'errores_sql' => $errores));
