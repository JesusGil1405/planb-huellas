<?php
/**
 * Plan B Conector · comprobaciones de seguridad (1.7.39 · auditoría de seguridad del 26/11/2026, tanda 1).
 * Funciones puras (sin WordPress) que usan planb-conector.php, limpieza.php, restaurar.php y rescate.php.
 * Compatible con PHP 5.6 a 8.5. No hace nada si se abre directamente.
 *
 *  · planb_slug_ok                  nombres de plugin o tema: sin «..», «.», barras ni nada raro (S2, S3)
 *  · planb_tablas_propias_de        las tablas de ESTA web aunque otra comparta la base de datos (S39)
 *  · planb_puntos_a_borrar          qué puntos viejos se pueden borrar sin quitar el respaldo de otro trabajo (S40)
 *  · planb_sql_sentencia_permitida  al restaurar, nada de otras bases, usuarios ni tablas de otra web (S46)
 *  · planb_zip_entrada_permitida    al restaurar, ningún .php dentro de uploads (S46)
 *  · planb_punto_completo           solo cuentan los puntos que tienen base de datos y archivos (S46)
 *  · planb_sql_ejecutar             restaura un volcado contando errores, bloqueadas y si quedó a medias (S46)
 *  · planb_archivo_php_*            volcado e info como .php que no muestran nada aunque el servidor sea nginx (S13)
 *  · planb_misma_base               los paquetes solo se bajan de la dirección EXACTA del panel (S14)
 */
if (!defined('ABSPATH') && !defined('PLANB_RESTAURAR_LIB')) { if (function_exists('http_response_code')) http_response_code(404); exit; }

if (!defined('PLANB_PHP_CABECERA')) define('PLANB_PHP_CABECERA', "<?php exit; ?>\n");

function planb_slug_ok($s)
{
    return is_string($s) && preg_match('/^[a-z0-9][a-z0-9_-]{0,99}$/i', $s) === 1;
}

/**
 * Tablas de la web con el prefijo $pre, sin las de otra web de la misma base (p. ej. wp_ y wp_tienda_).
 * Otra web = otro prefijo más largo que empieza por $pre y tiene su propia tabla de ajustes y de contenido
 * (WordPress: options + posts; PrestaShop: configuration + product). Con prefijo vacío no devuelve nada.
 */
function planb_tablas_propias_de(array $todas, $pre)
{
    $pre = (string)$pre;
    if ($pre === '') return array();
    $hay = array_flip($todas);
    $otros = array();
    foreach ($todas as $t) {
        $p = null;
        if (substr($t, -7) === 'options' && isset($hay[substr($t, 0, -7) . 'posts'])) $p = substr($t, 0, -7);
        elseif (substr($t, -13) === 'configuration' && isset($hay[substr($t, 0, -13) . 'product'])) $p = substr($t, 0, -13);
        if ($p !== null && $p !== $pre && strlen($p) > strlen($pre) && strpos($p, $pre) === 0) $otros[] = $p;
    }
    $r = array();
    foreach ($todas as $t) {
        if (strpos($t, $pre) !== 0) continue;
        $deOtra = false;
        foreach ($otros as $o) if (strpos($t, $o) === 0) { $deOtra = true; break; }
        if (!$deOtra) $r[] = $t;
    }
    return $r;
}

/** Con WordPress: las tablas de esta web (o del prefijo dado) en su base de datos. */
function planb_tablas_propias($pre = null)
{
    global $wpdb;
    return planb_tablas_propias_de((array)$wpdb->get_col('SHOW TABLES'), $pre === null ? $wpdb->prefix : $pre);
}

/** Fecha (timestamp) de un id de punto «Ymd-His-…», o 0. */
function planb_punto_fecha($id)
{
    if (!preg_match('/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})-/', (string)$id, $m)) return 0;
    return (int)gmmktime((int)$m[4], (int)$m[5], (int)$m[6], (int)$m[2], (int)$m[3], (int)$m[1]);
}

/**
 * Qué puntos se pueden borrar al crear uno nuevo: los más viejos mientras queden 2 o más, pero nunca los que el panel
 * pide conservar (respaldo de un trabajo en curso) ni los de menos de 6 horas; siempre quedan al menos 2 además del nuevo.
 * Si quedarían más de 4, también los no protegidos de más de 30 minutos; si aun así no cabe, 'lleno'.
 * $ids: los puntos que hay (sin el nuevo). Devuelve la lista a borrar o la cadena 'lleno'.
 */
function planb_puntos_a_borrar(array $ids, array $conservar, $ahora)
{
    sort($ids);
    $borrar = array(); $quedan = count($ids);
    foreach ($ids as $id) {
        if ($quedan <= 2) break;
        if (in_array($id, $conservar, true)) continue;
        $f = planb_punto_fecha($id);
        if ($f > 0 && $f > (int)$ahora - 6 * 3600) continue;
        $borrar[] = $id; $quedan--;
    }
    // Si aun así quedan más de 4, se borran los más viejos que no se piden conservar y tienen más de 30 minutos
    // (el panel hace un trabajo por web a la vez: un punto de hace más de 30 min no es el de un trabajo en marcha)
    if ($quedan > 4) foreach ($ids as $id) {
        if ($quedan <= 4) break;
        if (in_array($id, $borrar, true) || in_array($id, $conservar, true)) continue;
        $f = planb_punto_fecha($id);
        if ($f > 0 && $f > (int)$ahora - 1800) continue;
        $borrar[] = $id; $quedan--;
    }
    if ($quedan > 4) return 'lleno';
    return $borrar;
}

/**
 * ¿Se puede ejecutar esta sentencia al restaurar? Nada de otras bases ni usuarios ni ajustes globales, y las tablas
 * tienen que ser de esta web ($prefijo, sin las de otra web de la misma base: $otros = sus prefijos).
 */
function planb_sql_sentencia_permitida($sql, $prefijo, array $otros = array())
{
    $s = ltrim(preg_replace('#^(\s*(/\*(?!!).*?\*/|--[^\n]*\n))+#s', '', (string)$sql));
    if ($s === '') return true;
    if (preg_match('/^(DROP|CREATE|ALTER)\s+(DATABASE|SCHEMA|USER|EVENT|TRIGGER|PROCEDURE|FUNCTION|SERVER)\b/i', $s)) return false;
    if (preg_match('/^(USE|GRANT|REVOKE|LOAD\s+DATA|LOAD\s+XML|RENAME\s+USER|SHUTDOWN|KILL|FLUSH|INSTALL|UNINSTALL|HANDLER|CALL|DO|PREPARE|EXECUTE)\b/i', $s)) return false;
    if (preg_match('/^SET\b/i', $s)) {
        if (preg_match('/^SET\s+(GLOBAL|PASSWORD|@@GLOBAL|PERSIST)/i', $s) || preg_match('/@@global/i', $s)) return false;
        return true;
    }
    if (preg_match('/^\/\*!\d*\s*SET\b/i', $s)) return !preg_match('/GLOBAL|PASSWORD/i', $s);
    if (preg_match('/^(UNLOCK\s+TABLES)\b/i', $s)) return true;
    if (!preg_match('/^(DROP\s+TABLE(?:\s+IF\s+EXISTS)?|CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?|INSERT(?:\s+IGNORE)?\s+INTO|REPLACE\s+INTO|ALTER\s+TABLE|LOCK\s+TABLES|TRUNCATE(?:\s+TABLE)?)\s+(`[^`]+`(?:\s*\.\s*`[^`]+`)?|[A-Za-z0-9_$.]+)/i', $s, $m)) return false;
    $t = $m[2];
    if (strpos(str_replace('``', '', $t), '.') !== false) return false; // otra_bd.tabla
    $t = trim($t, '`');
    if ((string)$prefijo === '' || strpos($t, (string)$prefijo) !== 0) return false;
    foreach ($otros as $o) if ($o !== '' && $o !== $prefijo && strpos($t, $o) === 0) return false;
    return true;
}

/** Prefijos de otras webs en la misma base (para planb_sql_sentencia_permitida). */
function planb_otros_prefijos(array $todas, $pre)
{
    $otros = array();
    foreach (array_diff($todas, planb_tablas_propias_de($todas, $pre)) as $t) {
        if (substr($t, -7) === 'options') $otros[] = substr($t, 0, -7);
        if (substr($t, -13) === 'configuration') $otros[] = substr($t, 0, -13);
    }
    return array_values(array_unique($otros));
}

/** ¿Se puede sacar esta entrada del zip al restaurar? Ningún ejecutable dentro de uploads (ni con doble extensión). */
function planb_zip_entrada_permitida($nombre)
{
    $n = str_replace('\\', '/', (string)$nombre);
    if ($n === '' || $n[0] === '/' || preg_match('#(^|/)\.\.(/|$)#', $n)) return false;
    if (stripos($n, 'wp-content/uploads/') === 0 && preg_match('/\.(php\d?|phtml|phar|pht|phps|shtml|cgi|pl|py|htaccess|user\.ini)(\.|$)/i', basename($n))) return false;
    if (stripos($n, 'wp-content/uploads/') === 0 && in_array(strtolower(basename($n)), array('.htaccess', '.user.ini'), true)) return false;
    return true;
}

/** Ruta del volcado de un punto: el nuevo (bd.sql.php) o el antiguo (bd.sql). */
function planb_punto_sql($dir)
{
    if (is_file($dir . '/bd.sql.php')) return $dir . '/bd.sql.php';
    return $dir . '/bd.sql';
}

/** Información de un punto (info.php nuevo o info.json antiguo). */
function planb_punto_info($dir)
{
    if (is_file($dir . '/info.php')) return json_decode(planb_archivo_php_leer($dir . '/info.php'), true);
    if (is_file($dir . '/info.json')) return json_decode((string)@file_get_contents($dir . '/info.json'), true);
    return null;
}

/** Un punto vale si tiene base de datos y archivos con contenido y, si es nuevo, se terminó de crear. */
function planb_punto_completo($dir)
{
    clearstatcache();
    $sql = planb_punto_sql($dir);
    if (!is_file($sql) || (int)@filesize($sql) <= strlen(PLANB_PHP_CABECERA)) return false;
    if (!is_file($dir . '/archivos.zip') || (int)@filesize($dir . '/archivos.zip') <= 0) return false;
    $info = planb_punto_info($dir);
    if (is_file($dir . '/info.php')) return is_array($info) && !empty($info['completo']);
    return true; // punto antiguo (antes de la 1.7.39): sin marca de completo
}

/** Escribe un archivo .php que no enseña nada si alguien lo pide por la web (nginx no lee .htaccess). */
function planb_archivo_php_escribir($ruta, $texto)
{
    return @file_put_contents($ruta, PLANB_PHP_CABECERA . $texto) !== false;
}
function planb_archivo_php_leer($ruta)
{
    $t = (string)@file_get_contents($ruta);
    return strpos($t, PLANB_PHP_CABECERA) === 0 ? (string)substr($t, strlen(PLANB_PHP_CABECERA)) : $t;
}
/** Abre el volcado para escribir (con la cabecera .php ya puesta). */
function planb_sql_abrir_escritura($ruta)
{
    $h = @fopen($ruta, 'w');
    if ($h && fwrite($h, PLANB_PHP_CABECERA) === false) { fclose($h); return false; }
    return $h;
}

/** Una sentencia está completa si no queda una comilla simple abierta. */
function planb_sql_completa($s)
{
    $s = str_replace(array('\\\\', "\\'"), '', $s);
    return substr_count($s, "'") % 2 === 0;
}

/**
 * Ejecuta un volcado sentencia a sentencia. $ejecutor($sql) devuelve true si fue bien. $permitida($sql) decide si se
 * ejecuta (las no permitidas se saltan y se cuentan). Devuelve array(errores, hechas, bloqueadas, incompleta).
 */
function planb_sql_ejecutar($ruta, $ejecutor, $permitida = null)
{
    $r = array('errores' => 0, 'hechas' => 0, 'bloqueadas' => 0, 'incompleta' => false);
    $h = @fopen($ruta, 'r');
    if (!$h) { $r['errores'] = 1; $r['incompleta'] = true; return $r; }
    $buf = ''; $primera = true;
    while (($l = fgets($h)) !== false) {
        if ($primera) { $primera = false; if ($l === PLANB_PHP_CABECERA || rtrim($l) === rtrim(PLANB_PHP_CABECERA)) continue; }
        $buf .= $l;
        if (substr(rtrim($l), -1) === ';' && planb_sql_completa($buf)) {
            // Puntos hechos antes de la 1.7.4: el «%» quedó guardado como {hash de 64}; se devuelve a «%»
            $buf = preg_replace('/\{[0-9a-f]{64}\}/', '%', $buf);
            if ($permitida && !call_user_func($permitida, $buf)) $r['bloqueadas']++;
            elseif (call_user_func($ejecutor, $buf)) $r['hechas']++;
            else $r['errores']++;
            $buf = '';
        }
    }
    fclose($h);
    if (trim($buf) !== '') { $r['errores']++; $r['incompleta'] = true; }
    return $r;
}

/** ¿$url es de la misma dirección que el panel? Esquema, nombre (con o sin www.) y puerto iguales. */
function planb_misma_base($url, $panel)
{
    $a = parse_url((string)$url); $b = parse_url((string)$panel);
    if (empty($a['host']) || empty($b['host']) || empty($a['scheme']) || empty($b['scheme'])) return false;
    $ea = strtolower($a['scheme']); $eb = strtolower($b['scheme']);
    if ($ea !== $eb) return false;
    $ha = preg_replace('/^www\./', '', strtolower($a['host'])); $hb = preg_replace('/^www\./', '', strtolower($b['host']));
    if ($ha !== $hb) return false;
    $pd = $ea === 'https' ? 443 : 80;
    $pa = isset($a['port']) ? (int)$a['port'] : $pd; $pb = isset($b['port']) ? (int)$b['port'] : $pd;
    return $pa === $pb;
}
