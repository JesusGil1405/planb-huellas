<?php
/**
 * Restauración SEGURA de los archivos de un punto (1.7.37 · Jesús, 26/11/2026, tras la caída de León).
 * La usan planb-conector.php (restaurar) y rescate.php (sin WordPress). Compatible con PHP 5.6 a 8.5.
 *
 * Antes se borraban todos los plugins y temas y DESPUÉS se extraía el zip: si la extracción fallaba a medias, la web
 * quedaba sin plugins ni tema. Ahora:
 *   1) se extrae el zip entero en una carpeta temporal dentro del punto (si falla, no se ha tocado nada);
 *   2) se cambia cada plugin y tema por su copia (el actual va a una papelera dentro del punto, no se borra);
 *   3) el resto de archivos se extrae encima;
 *   4) se comprueba que cada plugin y tema del punto está en su sitio; si falta alguno, se devuelve desde la papelera.
 * Este archivo no hace nada si se abre directamente.
 */
if (!defined('PLANB_RESTAURAR_LIB')) { if (function_exists('http_response_code')) http_response_code(404); exit; }

function planb_rs_borrar($d)
{
    if (is_link($d) || is_file($d)) return @unlink($d);
    if (!is_dir($d)) return false;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) { if ($f->isDir() && !$f->isLink()) @rmdir($f->getPathname()); else @unlink($f->getPathname()); }
    return @rmdir($d);
}
function planb_rs_copiar($de, $a)
{
    if (is_file($de)) { @mkdir(dirname($a), 0755, true); return @copy($de, $a); }
    if (!is_dir($de)) return false;
    @mkdir($a, 0755, true);
    $ok = true;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($de, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    foreach ($it as $f) {
        $dest = $a . substr($f->getPathname(), strlen($de));
        if ($f->isDir()) { if (!is_dir($dest) && !@mkdir($dest, 0755, true)) $ok = false; }
        elseif (!@copy($f->getPathname(), $dest)) $ok = false;
    }
    return $ok;
}
/** Mueve (rename y, si no se puede, copia y borra). */
function planb_rs_mover($de, $a)
{
    if (@rename($de, $a)) return true;
    if (planb_rs_copiar($de, $a)) { planb_rs_borrar($de); return true; }
    return false;
}

/** Paso 1: extrae el zip del punto en una carpeta temporal. Devuelve array('ok'=>bool, 'tmp'=>…, 'error'=>…). Aún no se toca la web. */
function planb_rs_preparar($dirPunto)
{
    if (!class_exists('ZipArchive')) return array('ok' => false, 'error' => 'sin ZipArchive');
    $tmp = $dirPunto . '/extraido';
    if (file_exists($tmp)) planb_rs_borrar($tmp);
    $zip = new ZipArchive();
    if ($zip->open($dirPunto . '/archivos.zip') !== true) return array('ok' => false, 'error' => 'no se pudo abrir el zip del punto');
    $n = $zip->numFiles;
    if ($n < 10) { $zip->close(); return array('ok' => false, 'error' => 'el zip del punto está vacío (' . $n . ' entradas)'); }
    // Nada fuera de la carpeta: ni rutas absolutas ni «..»
    $permitidas = array(); $quitados = array();
    for ($i = 0; $i < $n; $i++) {
        $nom = (string)$zip->getNameIndex($i);
        if ($nom === '' || $nom[0] === '/' || preg_match('#(^|/)\.\.(/|$)#', $nom) || strpos($nom, '\\') !== false) { $zip->close(); return array('ok' => false, 'error' => 'el zip trae rutas no válidas'); }
        // 1.7.39 (auditoría S46): ningún ejecutable dentro de uploads
        if (function_exists('planb_zip_entrada_permitida') && !planb_zip_entrada_permitida($nom)) { $quitados[] = $nom; continue; }
        $permitidas[] = $nom;
    }
    @mkdir($tmp, 0755, true);
    $ok = $quitados ? $zip->extractTo($tmp, $permitidas) : $zip->extractTo($tmp);
    $zip->close();
    if (!$ok) { planb_rs_borrar($tmp); return array('ok' => false, 'error' => 'no se pudo extraer el zip (¿falta espacio?). La web no se ha tocado'); }
    return array('ok' => true, 'tmp' => $tmp, 'entradas' => $n, 'quitados' => array_slice($quitados, 0, 50));
}

/**
 * Paso 2: cambia plugins y temas por los del punto y copia el resto de archivos encima.
 * $raiz = ABSPATH sin barra final; $contenido = wp-content.
 * Devuelve array('ok'=>bool, 'problemas'=>array()).
 */
function planb_rs_cambiar($dirPunto, $tmp, $raiz, $contenido)
{
    $pap = $dirPunto . '/papelera-' . date('His');
    @mkdir($pap, 0755, true);
    $problemas = array();
    $relCont = ltrim(substr($contenido, strlen($raiz)), '/'); // normalmente «wp-content»
    foreach (array('plugins', 'themes') as $c) {
        $actual = $contenido . '/' . $c;
        $nuevo = $tmp . '/' . $relCont . '/' . $c;
        @mkdir($pap . '/' . $c, 0755, true);
        // Lo que hay ahora y no está en el punto → a la papelera; lo que está en los dos → se cambia
        foreach ((array)glob($actual . '/*') as $p) {
            $b = basename($p);
            if ($b === 'planb-conector') continue;
            if (!planb_rs_mover($p, $pap . '/' . $c . '/' . $b)) $problemas[] = "no se pudo apartar $c/$b";
        }
        foreach ((array)glob($nuevo . '/*') as $p) {
            $b = basename($p);
            if ($b === 'planb-conector') continue;
            if (!planb_rs_mover($p, $actual . '/' . $b)) $problemas[] = "no se pudo poner $c/$b";
        }
        // Comprobación: cada plugin o tema del punto tiene que estar en su sitio; si no, se devuelve el que había
        foreach ((array)glob($pap . '/' . $c . '/*') as $p) {
            $b = basename($p);
            if (!file_exists($actual . '/' . $b) && in_array("no se pudo poner $c/$b", $problemas, true)) planb_rs_mover($p, $actual . '/' . $b);
        }
        if (is_dir($nuevo)) planb_rs_borrar($nuevo);
    }
    // El resto (núcleo de WordPress, wp-config, mu-plugins…) se copia encima
    if (!planb_rs_copiar($tmp, $raiz)) $problemas[] = 'algunos archivos del núcleo no se pudieron copiar';
    planb_rs_borrar($tmp);
    if (!$problemas) planb_rs_borrar($pap);
    return array('ok' => !$problemas, 'problemas' => $problemas);
}

/**
 * Candado de la web en el propio servidor: un solo trabajo pesado a la vez (actualizar, restaurar, limpiar, optimizar…).
 * Archivo creado en modo exclusivo («x»): dos peticiones a la vez no pueden cogerlo las dos. Si un trabajo murió sin
 * soltarlo, caduca a los 30 minutos (los trabajos tienen como mucho 15 minutos).
 */
function planb_rs_ocupar($dirPuntos, $que)
{
    $f = $dirPuntos . '/ocupado.lock';
    if (!is_dir($dirPuntos)) @mkdir($dirPuntos, 0755, true);
    for ($i = 0; $i < 2; $i++) {
        $h = @fopen($f, 'x');
        if ($h) { fwrite($h, json_encode(array('que' => $que, 'desde' => time()))); fclose($h); $GLOBALS['planb_rs_ocupado'] = $f; register_shutdown_function('planb_rs_liberar'); return true; }
        clearstatcache();
        if (is_file($f) && filemtime($f) < time() - 1800) { @unlink($f); continue; }
        return false;
    }
    return false;
}
function planb_rs_liberar()
{
    if (!empty($GLOBALS['planb_rs_ocupado'])) { @unlink($GLOBALS['planb_rs_ocupado']); $GLOBALS['planb_rs_ocupado'] = null; }
}
function planb_rs_ocupado_info($dirPuntos)
{
    $f = $dirPuntos . '/ocupado.lock';
    if (!is_file($f)) return null;
    $j = json_decode((string)@file_get_contents($f), true);
    return array('que' => is_array($j) && isset($j['que']) ? (string)$j['que'] : '?', 'desde' => (int)@filemtime($f));
}
