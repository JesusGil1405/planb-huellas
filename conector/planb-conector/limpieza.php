<?php

/** unserialize sin crear objetos de clases (una web hackeada puede tener datos preparados para eso). Los objetos se
 *  quedan como «clase incompleta» y, al volver a guardarlos, conservan su clase original. (1.7.24 · auditoría) */
if (!function_exists('planb_unserialize_seguro')) {
    function planb_unserialize_seguro($v)
    {
        return version_compare(PHP_VERSION, '7.0', '>=') ? @unserialize($v, array('allowed_classes' => false)) : @unserialize($v); // nosemgrep: unserialize-de-fuera — sin clases desde PHP 7
    }
}
/*
 * Plan B Conector · ESCANEO A FONDO Y LIMPIEZA DE HACKEOS.
 * Escrito compatible con PHP 5.6 a 8.5 (webs antiguas, que son las que más se hackean).
 *
 *  · escanear (solo lee): archivos sospechosos (código ofuscado, PHP en uploads, plugins de wordpress.org que no coinciden
 *    con los oficiales), .htaccess y wp-config raros, spam en la base de datos (todas las tablas), administradores,
 *    registro abierto, y la portada vista como un visitante y como Google (para ver el spam oculto).
 *  · limpiar: lo que el panel mande, siempre de forma reversible: los archivos van a una CUARENTENA (no se borran),
 *    lo que se cambia en la base de datos se guarda antes, y wp-config.php se copia antes de tocarlo.
 *    El punto de restauración completo lo crea el panel antes de llamar aquí.
 */
if (!defined('ABSPATH')) exit;

/**
 * Spam fuerte: marcas y marcadores que casi nunca salen en una web legítima. Marcan EN CUALQUIER SITIO.
 * (Jesús, 22/11/2026: se quitó «tipico» y palabras genéricas que picaban con texto bueno.)
 */
function planb_spam_fuerte()
{
    return '/(betway|bet365|bwin|stake\.com|leovegas|joycasino|melbet|1xbet|parimatch|mostbet|vavada|1win|1вин|1хбет|казио|казино|пинко|пин ?ап|ставк|букмекер|игровые автоматы|kasyno|kaszin|xr-verify|data-xr=|xrv-[0-9a-f]{6,}|\\bcasinos?\\b|\\bkazino\\b|\\b(viagra|cialis|levitra)\\b)/iu';
}

/**
 * Spam débil: palabras genéricas de juego/spam que SÍ pueden salir en texto legítimo (o en un enlace bueno).
 * Solo cuentan como hackeo cuando aparecen DENTRO de un enlace a OTRA web (la firma del spam).
 */
function planb_spam_debil()
{
    return '/(poker|gambl|apuestas|slot[s]?\b|bet(ting|s)?\b|bonus(es)?\b|wager|jackpot|free ?spins?|payday|loan[s]? online|aviator|pin-?up|scommess|wetten|ruleta|roulette|replica watch)/iu';
}

/** Combinado (para el limpiador, que solo actúa sobre enlaces externos ya filtrados por dominio). */
function planb_spam_regex()
{
    return '/(' . substr(planb_spam_fuerte(), 2, -4) . '|' . substr(planb_spam_debil(), 2, -4) . ')/iu';
}

/**
 * Cuenta el spam de un texto SIN marcar enlaces externos buenos (Jesús, 22/11/2026):
 *   · spam fuerte: en cualquier parte.
 *   · spam débil: solo dentro de un enlace <a> que apunta a OTRA web (no la propia).
 * Devuelve array(cuántas, posición del primer hallazgo).
 */
function planb_spam_cuenta($v)
{
    $n = preg_match_all(planb_spam_fuerte(), $v, $mf, PREG_OFFSET_CAPTURE);
    $pos = $n ? $mf[0][0][1] : -1;
    $host = preg_replace('/^www\./', '', strtolower((string)parse_url(home_url(), PHP_URL_HOST)));
    $deb = planb_spam_debil();
    if (preg_match_all('/<a\s[^>]*href\s*=\s*["\']?\s*(?:https?:)?\/\/([^\/"\'\s>]+)[^>]*>.*?<\/a>/is', $v, $ma, PREG_OFFSET_CAPTURE)) {
        foreach ($ma[1] as $i => $dm) {
            $dom = preg_replace('/^www\./', '', strtolower($dm[0]));
            if ($host !== '' && ($dom === $host || substr($dom, -strlen('.' . $host)) === '.' . $host)) continue; // enlace a la propia web: no es spam
            $c = preg_match_all($deb, $ma[0][$i][0]);
            if ($c) { $n += $c; if ($pos < 0) $pos = $ma[0][$i][1]; }
        }
    }
    return array($n, $pos < 0 ? 0 : $pos);
}

/** Patrones de código malicioso en archivos: [regex, peso, explicación]. */
function planb_patrones_codigo()
{
    return array(
        array('/eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin|\$_(POST|GET|REQUEST|COOKIE|SERVER))/i', 10, 'eval() con código oculto'),
        array('/assert\s*\(\s*(\$_(POST|GET|REQUEST|COOKIE)|base64_decode|str_rot13)/i', 10, 'assert() con datos de fuera'),
        array('/preg_replace\s*\(\s*[\'"](.).*\1[a-z]*e[a-z]*[\'"]\s*,/i', 8, 'preg_replace con /e (ejecuta código)'),
        array('/create_function\s*\(.*\$_(POST|GET|REQUEST|COOKIE)/i', 10, 'create_function con datos de fuera'),
        array('/(gzinflate|gzuncompress|str_rot13)\s*\(\s*base64_decode/i', 9, 'código comprimido y oculto'),
        array('/base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=\s]{400,}/', 6, 'bloque largo en base64'),
        array('/(\\\\x[0-9a-f]{2}){40,}/i', 6, 'texto oculto en hexadecimal'),
        array('/\$\w+\s*=\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]+\]\s*;\s*@?\$\w+\s*\(/i', 9, 'ejecuta lo que llega por la URL'),
        array('/@?\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i', 10, 'puerta trasera (webshell)'),
        array('/(file_put_contents|fwrite)\s*\([^;]*\$_(POST|GET|REQUEST|FILES)/i', 7, 'escribe archivos con datos de fuera'),
        array('/move_uploaded_file\s*\([^;]*\$_FILES/i', 3, 'sube archivos'),
        array('/(passthru|shell_exec|system|proc_open|popen)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i', 10, 'ejecuta comandos del servidor'),
        array('/\b(wso\s*shell|wso_version|b374k|c99shell|c99_buff|r57shell|filesman|alfa\s?shell|indoxploit)\b/i', 8, 'nombre de webshell conocida'),
        array('/@include\s*\(?\s*[\'"][^\'"]+\.(ico|png|jpg|gif|txt)[\'"]/i', 9, 'incluye código escondido en una imagen'),
        array('/xrv-[0-9a-f]{6,}/i', 9, 'marca de la campaña de spam'),
        array('/(casino|mostbet|1win|vavada|pinco|free ?spins|viagra|cialis)/i', 4, 'palabras de spam'),
        array('/(document\.write\s*\(\s*unescape|eval\s*\(\s*String\.fromCharCode|eval\s*\(\s*atob\s*\()/i', 8, 'JavaScript ofuscado'),
        array('/googlebot|bingbot|yandex/i', 1, 'trato distinto a los buscadores'),
        array('/(wp_insert_user|wp_create_user)\s*\([^;]*administrator/i', 8, 'crea administradores'),
        array('/HTTP_USER_AGENT.*(google|bing)/i', 3, 'trato distinto a Google'),
    );
}

function planb_rel($ruta)
{
    $base = rtrim(str_replace('\\', '/', ABSPATH), '/') . '/';
    $r = str_replace('\\', '/', $ruta);
    return strpos($r, $base) === 0 ? substr($r, strlen($base)) : $r;
}

function planb_muestra($txt, $pos, $ancho)
{
    $ini = max(0, $pos - (int)($ancho / 2));
    $s = substr($txt, $ini, $ancho);
    $s = preg_replace('/[^\P{C}\n\t]/u', '', (string)$s);
    if ($s === null || $s === '') $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', substr($txt, $ini, $ancho));
    return mb_substr((string)$s, 0, $ancho);
}

/** Puntúa un archivo. Devuelve null si no es sospechoso o [peso, motivos, muestra]. */
function planb_analizar_archivo($ruta, $enUploads)
{
    $ext = strtolower(pathinfo($ruta, PATHINFO_EXTENSION));
    $tam = @filesize($ruta);
    if ($tam === false || $tam > 3 * 1048576) return null;
    $esPhp = in_array($ext, array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'inc', 'pht'), true);
    $txt = (string)@file_get_contents($ruta, false, null, 0, 3 * 1048576);
    if (!$esPhp) {
        // Imágenes o .ico con PHP dentro, o JS de temas con código ofuscado
        if (in_array($ext, array('ico', 'png', 'jpg', 'gif', 'txt', 'svg'), true) && strpos($txt, '<?php') !== false) return array(10, array('código PHP escondido en un archivo ' . $ext), planb_muestra($txt, strpos($txt, '<?php'), 160));
        if ($ext !== 'js') return null;
    }
    // Archivos propios de plugins de seguridad conocidos guardados en uploads (reglas del cortafuegos de All In One WP Security)
    if ($esPhp && $enUploads && preg_match('#/uploads/aios/#', str_replace('\\', '/', $ruta)) && strpos($txt, 'aiowps') !== false) return null;
    // En PHP se analiza el código sin comentarios (un ejemplo comentado no es código que se ejecute)
    if ($esPhp && function_exists('token_get_all')) {
        $limpio = '';
        foreach (@token_get_all($txt) as $tk) { if (is_array($tk)) { if ($tk[0] === T_COMMENT || $tk[0] === T_DOC_COMMENT) continue; $limpio .= $tk[1]; } else $limpio .= $tk; }
        if ($limpio !== '') $txt = $limpio;
    }
    // 1.7.15: un index.php «vacío» en uploads (solo <?php, o un exit/die/403) es el que ponen los plugins para que no se
    // pueda listar la carpeta (AIOS lo pone en sus sesiones). No hace nada: no se marca.
    if ($esPhp && $enUploads && preg_match('/^\s*(<\?php)?\s*((header\s*\(\s*([\'"])[^\'"]*\4\s*(,\s*(true|false)\s*(,\s*\d+)?)?\s*\)\s*;|http_response_code\s*\(\s*\d+\s*\)\s*;)\s*)*((exit|die)\s*(\(\s*(([\'"])[^\'"]*\12|\d+)?\s*\))?\s*;?)?\s*(\?>)?\s*$/i', $txt)) return null;
    $peso = 0; $motivos = array(); $muestra = '';
    if ($esPhp && $enUploads) { $peso += 8; $motivos[] = 'archivo PHP dentro de uploads (ahí solo debería haber imágenes)'; }
    foreach (planb_patrones_codigo() as $p) {
        if ($ext === 'js' && $p[1] < 8) continue;
        if (preg_match($p[0], $txt, $m, PREG_OFFSET_CAPTURE)) {
            $peso += $p[1]; $motivos[] = $p[2];
            if ($muestra === '') $muestra = planb_muestra($txt, $m[0][1], 200);
        }
    }
    // Línea larguísima sin espacios: típico del código ofuscado
    if ($esPhp && preg_match('/[A-Za-z0-9+\/=]{3000,}/', $txt)) { $peso += 4; $motivos[] = 'línea de código muy larga y sin espacios (ofuscado)'; }
    if ($peso < 8) return null;
    return array($peso, $motivos, $muestra);
}

/** Sumas oficiales de un plugin de wordpress.org (null si no está en el directorio). */
function planb_sumas_plugin($slug, $version)
{
    $r = wp_remote_get('https://downloads.wordpress.org/plugin-checksums/' . rawurlencode($slug) . '/' . rawurlencode($version) . '.json', array('timeout' => 15));
    if (is_wp_error($r) || wp_remote_retrieve_response_code($r) !== 200) return null;
    $j = json_decode(wp_remote_retrieve_body($r), true);
    return isset($j['files']) && is_array($j['files']) ? $j['files'] : null;
}

function planb_escanear(WP_REST_Request $req)
{
    @set_time_limit(600);
    @ignore_user_abort(true);
    if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
    global $wpdb, $wp_version;
    $inicio = time();
    // Por fases (para servidores que cortan a los 45 s): plugins → archivos → bd → resto, cada una con su marcador «desde».
    // Sin fase: todo de una vez, como antes.
    $pr = (array)$req->get_json_params();
    $fase = isset($pr['fase']) ? (string)$pr['fase'] : '';
    $desde = isset($pr['desde']) ? (int)$pr['desde'] : 0;
    $por = $fase !== '';
    $tope = $por ? 28 : 0;
    $out = array('version_wp' => $wp_version, 'php' => PHP_VERSION, 'archivos' => array(), 'plugins' => array(), 'bd' => array(), 'config' => array(), 'admins' => array(), 'portada' => array(), 'avisos' => array());
    $contenido = rtrim(str_replace('\\', '/', WP_CONTENT_DIR), '/');
    $subidas = wp_upload_dir(); $subidas = rtrim(str_replace('\\', '/', $subidas['basedir']), '/');

    // 1 · Plugins: los de wordpress.org se comparan con los oficiales; los que coinciden no se analizan más
    $confiables = $por && $fase !== 'plugins' ? (array)get_option('planb_esc_confiables', array()) : array();
    if ($por && $fase === 'plugins' && $desde > 0) $confiables = (array)get_option('planb_esc_confiables', array());
    $iP = -1;
    foreach (($por && $fase !== 'plugins') ? array() : get_plugins() as $file => $d) {
        $iP++;
        if ($iP < $desde) continue;
        if ($por && $iP > $desde && time() - $inicio > $tope) { $out['sigue'] = $iP; break; }
        $slug = strpos($file, '/') !== false ? dirname($file) : basename($file, '.php');
        $info = array('archivo' => $file, 'slug' => $slug, 'nombre' => $d['Name'], 'version' => $d['Version'], 'activo' => is_plugin_active($file), 'oficial' => false, 'cambiados' => array(), 'anadidos' => array());
        if (strpos($file, '/') !== false && ($por || time() - $inicio < 12)) {
            $sumas = planb_sumas_plugin($slug, $d['Version']);
            if ($sumas !== null) {
                $info['oficial'] = true;
                $dir = WP_PLUGIN_DIR . '/' . $slug;
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
                foreach ($it as $f) {
                    $rel = substr(str_replace('\\', '/', $f->getPathname()), strlen(str_replace('\\', '/', $dir)) + 1);
                    $abs = str_replace('\\', '/', $f->getPathname());
                    if (isset($sumas[$rel])) {
                        $md5 = $sumas[$rel]['md5'];
                        $ok = is_array($md5) ? in_array(md5_file($abs), $md5, true) : md5_file($abs) === $md5;
                        if ($ok) { $confiables[$abs] = 1; continue; }
                        $info['cambiados'][] = $rel;
                    } elseif (preg_match('/\.(php|phtml|phar|inc|ico|js)$/i', $rel)) {
                        $info['anadidos'][] = $rel;
                    } else {
                        $confiables[$abs] = 1;
                    }
                }
            }
        }
        $out['plugins'][] = $info;
    }
    if ($por && $fase === 'plugins') { update_option('planb_esc_confiables', $confiables, false); $out['segundos'] = time() - $inicio; return $out; }

    // 2 · Archivos de todo wp-content y la raíz (los de WordPress ya los revisa la integridad)
    $saltar = '#/(planb-puntos|planb-cuarentena|cache|upgrade|ai1wm-backups|updraft|backups?-dup-lite|node_modules|\.git)(/|$)#i';
    $vistos = 0;
    $raiz = rtrim(str_replace('\\', '/', ABSPATH), '/');
  if (!$por || $fase === 'archivos') {
    foreach ($desde > 0 ? array() : (array)glob($raiz . '/*') as $f) {
        if (!is_file($f)) continue;
        $f = str_replace('\\', '/', $f);
        $base = basename($f);
        if (in_array($base, array('wp-config.php', 'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php'), true)) {
            if ($base === 'index.php' || $base === 'wp-config.php') { $a = planb_analizar_archivo($f, false); if ($a) $out['archivos'][] = array('ruta' => planb_rel($f), 'peso' => $a[0], 'motivos' => $a[1], 'muestra' => $a[2], 'tam' => filesize($f), 'fecha' => date('Y-m-d H:i', filemtime($f))); }
            continue;
        }
        if (preg_match('/\.(php|phtml|phar|php\d)$/i', $base)) {
            $a = planb_analizar_archivo($f, false);
            $out['archivos'][] = array('ruta' => planb_rel($f), 'peso' => $a ? $a[0] + 2 : 3, 'motivos' => array_merge(array('archivo PHP suelto en la raíz que no es de WordPress'), $a ? $a[1] : array()), 'muestra' => $a ? $a[2] : planb_muestra((string)@file_get_contents($f, false, null, 0, 400), 0, 160), 'tam' => filesize($f), 'fecha' => date('Y-m-d H:i', filemtime($f)));
        }
    }
    $it = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(new RecursiveDirectoryIterator($contenido, FilesystemIterator::SKIP_DOTS), function ($f) use ($saltar) {
        return !preg_match($saltar, str_replace('\\', '/', $f->getPathname()));
    }));
    $pos = 0;
    foreach ($it as $f) {
        if ($pos++ < $desde) continue;
        if ($por && $pos - 1 > $desde && time() - $inicio > $tope) { $out['sigue'] = $pos - 1; break; }
        if (!$por && time() - $inicio > 22) { $out['avisos'][] = 'No ha dado tiempo a revisar todos los archivos (' . $vistos . ' revisados).'; break; }
        if (!$f->isFile()) continue;
        $abs = str_replace('\\', '/', $f->getPathname());
        if (isset($confiables[$abs])) continue;
        if (strpos($abs, WP_PLUGIN_DIR . '/planb-conector/') === 0) continue;
        $ext = strtolower($f->getExtension());
        if (!in_array($ext, array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'inc', 'pht', 'ico', 'js', 'png', 'jpg', 'gif', 'txt', 'svg'), true)) continue;
        if (in_array($ext, array('png', 'jpg', 'gif', 'svg', 'txt'), true) && $f->getSize() > 2 * 1048576) continue;
        $vistos++;
        $enUploads = strpos($abs, $subidas . '/') === 0;
        $a = planb_analizar_archivo($abs, $enUploads);
        if ($a) $out['archivos'][] = array('ruta' => planb_rel($abs), 'peso' => $a[0], 'motivos' => $a[1], 'muestra' => $a[2], 'tam' => $f->getSize(), 'fecha' => date('Y-m-d H:i', $f->getMTime()));
    }
    $out['archivos_revisados'] = $vistos;
    if ($por) { $out['segundos'] = time() - $inicio; return $out; }
  }
  if (!$por || $fase === 'resto') {
    // mu-plugins y «drop-ins»: se cargan siempre y no se ven en la lista de plugins
    foreach (array_merge((array)glob($contenido . '/mu-plugins/*.php'), array_filter(array($contenido . '/advanced-cache.php', $contenido . '/db.php', $contenido . '/object-cache.php', $contenido . '/maintenance.php', $contenido . '/sunrise.php'), 'is_file')) as $f) {
        $out['config'][] = array('que' => 'Se carga siempre', 'ruta' => planb_rel($f), 'detalle' => planb_muestra((string)@file_get_contents($f, false, null, 0, 600), 0, 240));
    }
    // .htaccess de la raíz y de uploads
    foreach (array($raiz . '/.htaccess', $subidas . '/.htaccess', $contenido . '/.htaccess') as $h) {
        if (!is_file($h)) continue;
        $t = (string)@file_get_contents($h);
        if (preg_match('/(auto_prepend_file|auto_append_file|RewriteCond[^\n]*(HTTP_USER_AGENT|HTTP_REFERER)[^\n]*(google|bing|yahoo)|RewriteRule[^\n]*https?:\/\/(?!' . preg_quote((string)parse_url(home_url(), PHP_URL_HOST), '/') . '))/i', $t, $m, PREG_OFFSET_CAPTURE))
            $out['config'][] = array('que' => '.htaccess con reglas raras (redirige o carga código)', 'ruta' => planb_rel($h), 'detalle' => planb_muestra($t, $m[0][1], 240), 'grave' => true);
    }
    $cfg = (string)@file_get_contents(ABSPATH . 'wp-config.php');
    if ($cfg === '' && is_file(dirname(ABSPATH) . '/wp-config.php')) $cfg = (string)@file_get_contents(dirname(ABSPATH) . '/wp-config.php');
    if (preg_match('/(eval\s*\(|base64_decode|gzinflate|@include|include_once\s*\(\s*[\'"]\/)/i', $cfg, $m, PREG_OFFSET_CAPTURE))
        $out['config'][] = array('que' => 'wp-config.php con código raro', 'ruta' => 'wp-config.php', 'detalle' => planb_muestra($cfg, $m[0][1], 240), 'grave' => true);
    $out['debug'] = defined('WP_DEBUG') && WP_DEBUG;
    $out['errores_visibles'] = (bool)ini_get('display_errors');
  }

    // 3 · Base de datos: todas las tablas, columnas de texto
    $rx = planb_spam_regex();
    $terminos = array('xrv-', 'casino', 'mostbet', '1win', 'vavada', 'pinco', 'free spin', 'viagra', 'cialis', 'казино', 'eval(', 'base64_decode', 'document.write(unescape', 'String.fromCharCode');
    $tablas = $wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($wpdb->prefix) . '%'));
    // Entradas y páginas de spam creadas por el hackeo (título o dirección de casino): van a la papelera de WordPress
    $out['entradas'] = array();
    $likeT = array();
    foreach (array('casino', 'casinos', 'kasino', 'kasyn', 'kazin', 'aviator', 'pin-up', 'pinup', 'baccarat', 'roulette', 'blackjack', 'mostbet', '1win', 'vavada', 'pinco', 'betting', 'apuestas', 'slots', 'free-spins', 'spelpaus', 'scommesse', 'wetten', 'kasyno', 'viagra', 'cialis') as $term) {
        $likeT[] = "post_title LIKE '" . esc_sql('%' . $wpdb->esc_like($term) . '%') . "'";
        $likeT[] = "post_name LIKE '" . esc_sql('%' . $wpdb->esc_like($term) . '%') . "'";
    }
    $spamIds = array();
    $hacerBd = !$por || $fase === 'bd';
    foreach ((array)$wpdb->get_results("SELECT ID, post_title, post_name, post_status, post_type, post_date, post_author FROM {$wpdb->posts} WHERE post_type NOT IN ('revision','nav_menu_item','attachment') AND post_status<>'trash' AND (" . implode(' OR ', $likeT) . ") ORDER BY post_date DESC LIMIT 5000", ARRAY_A) as $e) {
        if (!preg_match($rx, $e['post_title'] . ' ' . $e['post_name'])) continue;
        $spamIds[(int)$e['ID']] = 1;
        $out['entradas'][] = array('id' => (int)$e['ID'], 'titulo' => mb_substr((string)$e['post_title'], 0, 120), 'estado' => $e['post_status'], 'tipo' => $e['post_type'], 'fecha' => substr((string)$e['post_date'], 0, 16), 'autor' => (int)$e['post_author']);
    }
    $out['entradas_total'] = count($out['entradas']);
    $out['entradas'] = array_slice($out['entradas'], 0, 3000);
    $iT = -1;
    foreach ($hacerBd ? $tablas : array() as $t) {
        $iT++;
        if ($iT < $desde) continue;
        if ($por && $iT > $desde && time() - $inicio > $tope) { $out['sigue'] = $iT; break; }
        if (!$por && time() - $inicio > 29) { $out['avisos'][] = 'No ha dado tiempo a revisar toda la base de datos.'; break; }
        // Registros de visitas, ataques y estadísticas: solo guardan lo que se ha visitado, no es lo que se ve en la web
        if (preg_match('/(_events|_log|_logs|logs?_|_audit|_activity|_stats|_visits?|_404|redirection_|wfhits|wflogs|wfblock|_sessions|actionscheduler)/i', substr($t, strlen($wpdb->prefix)))) continue;
        // 1.7.28: pedidos de la tienda (direcciones y nombres de clientes: «Casino Conde Luna» es un sitio de verdad) y
        // avisos internos de plugins (AIOSEO guarda texto codificado): no son lo que se ve en la web y daban falsos avisos
        if (preg_match('/(wc_orders|wc_order_|woocommerce_order_|aioseo_notifications|wc_customer_lookup|wc_admin_notes|wpml_mails|mail_logging|wp_mail_log|email_log|post_smtp_logs|wpmailsmtp_)/i', substr($t, strlen($wpdb->prefix)))) continue;
        $porTabla = 0;
        $cols = $wpdb->get_results('SHOW COLUMNS FROM `' . esc_sql($t) . '`', ARRAY_A);
        $pk = null; $txt = array();
        foreach ($cols as $c) {
            if ($c['Key'] === 'PRI' && $pk === null) $pk = $c['Field'];
            if (preg_match('/text|char|blob/i', $c['Type'])) $txt[] = $c['Field'];
        }
        if (!$pk || !$txt) continue;
        $conds = array();
        foreach ($txt as $c) foreach ($terminos as $term) $conds[] = '`' . esc_sql($c) . '` LIKE \'' . esc_sql('%' . $wpdb->esc_like($term) . '%') . '\'';
        $sel = '`' . esc_sql($pk) . '`, `' . implode('`, `', array_map('esc_sql', $txt)) . '`';
        $filas = $wpdb->get_results('SELECT ' . $sel . ' FROM `' . esc_sql($t) . '` WHERE ' . implode(' OR ', $conds) . ' LIMIT 300', ARRAY_A);
        foreach ((array)$filas as $f) {
            foreach ($txt as $c) {
                $v = (string)$f[$c];
                if ($v === '') continue;
                list($n, $npos) = planb_spam_cuenta($v);
                $codigo = preg_match('/(eval\s*\(|base64_decode\s*\(|document\.write\s*\(\s*unescape|String\.fromCharCode\s*\()/i', $v, $mc, PREG_OFFSET_CAPTURE);
                if (!$n && !$codigo) continue;
                // Opciones del propio conector o de cachés: se anotan aparte
                $nombre = '';
                if ($t === $wpdb->options) $nombre = (string)$wpdb->get_var($wpdb->prepare('SELECT option_name FROM `' . esc_sql($t) . '` WHERE option_id=%d', $f[$pk]));
                elseif ($t === $wpdb->posts) { $p = get_post((int)$f[$pk]); if ($p && ($p->post_type === 'revision' || $p->post_status === 'trash')) continue; $nombre = $p ? ($p->post_type === 'page' ? 'Página' : $p->post_type) . ': ' . $p->post_title . ($p->post_status !== 'publish' ? ' (' . $p->post_status . ')' : '') . ((int)get_option('page_on_front') === (int)$p->ID ? ' · PORTADA' : '') : ''; }
                if (strpos($nombre, 'planb_') === 0) continue;
                if ($t === $wpdb->posts && isset($spamIds[(int)$f[$pk]])) continue; // ya va como entrada de spam (a la papelera entera)
                // 1.7.28: post_id no es de texto y no viene en la consulta: se busca (antes estas comprobaciones nunca se hacían)
                if ($t === $wpdb->postmeta && !isset($f['post_id'])) $f['post_id'] = (int)$wpdb->get_var($wpdb->prepare('SELECT post_id FROM `' . esc_sql($t) . '` WHERE meta_id=%d', $f[$pk]));
                if ($t === $wpdb->postmeta && isset($f['post_id']) && isset($spamIds[(int)$f['post_id']])) continue;
                // 1.7.28: datos de pedidos de la tienda (dirección, nombre, empresa del comprador): nunca son spam publicado
                if ($t === $wpdb->postmeta && isset($f['post_id']) && in_array(get_post_type((int)$f['post_id']), array('shop_order', 'shop_order_refund', 'shop_order_placehold', 'shop_subscription'), true)) continue;
                // 1.7.28: un bloque codificado sin espacios (base64 de plugins) puede contener por azar «1win» o «pinco»: solo cuenta si además lleva código
                if (!$codigo && strlen($v) > 120 && !preg_match('/\s/', $v) && preg_match('/^[A-Za-z0-9+\/=]+$/', $v)) continue;
                // Lo que ya está en la papelera no se lista (se quita entero con «Vaciar la papelera del spam»)
                if ($t === $wpdb->postmeta && isset($f['post_id']) && get_post_status((int)$f['post_id']) === 'trash') continue;
                if (++$porTabla > 60) continue;
                $enlaces = preg_match_all('/<a\s[^>]*href=/i', $v, $tmp);
                $out['bd'][] = array('tabla' => $t, 'pk' => $pk, 'id' => (string)$f[$pk], 'columna' => $c, 'nombre' => $nombre, 'coincidencias' => $n, 'enlaces' => $enlaces, 'codigo' => (bool)$codigo, 'cache' => (bool)preg_match('/^_?(site_)?transient/', $nombre),
                    'muestra' => planb_muestra($v, $n ? $npos : $mc[0][1], 240), 'largo' => strlen($v));
                if (count($out['bd']) >= 400) break 3;
            }
        }
    }

    if ($por && $fase === 'bd') { if ($desde > 0) { unset($out['entradas']); unset($out['entradas_total']); } $out['segundos'] = time() - $inicio; return $out; }
    // 3b · Quién publica el spam: autores con entradas de spam (el atacante suele publicar con un usuario propio o robado)
    $porAutor = array();
    foreach ($out['entradas'] as $e) { $a = (int)$e['autor']; $porAutor[$a] = isset($porAutor[$a]) ? $porAutor[$a] + 1 : 1; }
    $out['usuarios'] = array();
    foreach (get_users(array('fields' => 'all', 'number' => 500)) as $u) {
        $n = (int)count_user_posts($u->ID, 'post', false);
        $ult = $wpdb->get_var($wpdb->prepare("SELECT MAX(post_date) FROM {$wpdb->posts} WHERE post_author=%d AND post_type='post'", $u->ID));
        $out['usuarios'][] = array('id' => (int)$u->ID, 'login' => $u->user_login, 'email' => $u->user_email, 'roles' => implode(',', (array)$u->roles), 'alta' => $u->user_registered,
            'entradas' => $n, 'spam' => isset($porAutor[(int)$u->ID]) ? $porAutor[(int)$u->ID] : 0, 'ultima' => (string)$ult);
    }
    $out['xmlrpc'] = (bool)apply_filters('xmlrpc_enabled', true);
    $out['papelera'] = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type='post' AND post_status='trash'");
    // Solo una muestra y con tope de tiempo: el arreglo de verdad va por tandas
    $tild = $por ? planb_filas_tildes(200, null, 10) : (time() - $inicio < 33 ? planb_filas_tildes(200, null, 4) : array());
    $out['tildes'] = count($tild);
    $out['tildes_ej'] = '';
    foreach ($tild as $f) { $v = (string)$wpdb->get_var($wpdb->prepare('SELECT `' . $f[3] . '` FROM `' . $f[0] . '` WHERE `' . $f[1] . '`=%s', $f[2])); if (preg_match(planb_tildes_rx(), $v, $m, PREG_OFFSET_CAPTURE)) { $out['tildes_ej'] = planb_muestra($v, $m[0][1], 60) . ' → ' . planb_arreglar_tildes(planb_muestra($v, $m[0][1], 60)); break; } }

    // 4 · Usuarios con poder y registro abierto
    foreach (get_users(array('role__in' => array('administrator'), 'fields' => array('ID', 'user_login', 'user_email', 'user_registered'), 'number' => 400)) as $u)
        $out['admins'][] = array('id' => (int)$u->ID, 'login' => $u->user_login, 'email' => $u->user_email, 'alta' => $u->user_registered, 'yo' => false);
    $out['registro_abierto'] = (bool)get_option('users_can_register');
    $out['rol_nuevos'] = (string)get_option('default_role');

    // 5 · La portada como la ve un visitante y como la ve Google
    foreach (array('visitante' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36', 'google' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)') as $k => $ua) {
        if (time() - $inicio > ($por ? 30 : 36)) { $out['portada'][$k] = array('error' => 'sin tiempo (la mira el panel)'); continue; }
        $r = wp_remote_get(home_url('/'), array('timeout' => 8, 'user-agent' => $ua, 'redirection' => 3, 'sslverify' => false)); // nosemgrep: tls-sin-verificar — la web se mira a sí misma (puede tener certificado propio)
        if (is_wp_error($r)) { $out['portada'][$k] = array('error' => $r->get_error_message()); continue; }
        $html = wp_remote_retrieve_body($r);
        list($n, $npos) = planb_spam_cuenta($html);
        $out['portada'][$k] = array('codigo' => wp_remote_retrieve_response_code($r), 'tam' => strlen($html), 'spam' => $n, 'enlaces' => preg_match_all('/<a\s/i', $html, $tmp),
            'muestra' => $n ? planb_muestra($html, $npos, 600) : '', 'redirige' => wp_remote_retrieve_header($r, 'location'));
    }
    if ($por) unset($out['entradas']);
    $out['segundos'] = time() - $inicio;
    return $out;
}

/* ───────────── Limpieza ───────────── */

function planb_dir_cuarentena()
{
    $d = WP_CONTENT_DIR . '/planb-cuarentena';
    if (!is_dir($d)) {
        wp_mkdir_p($d);
        @file_put_contents($d . '/.htaccess', "Require all denied\nDeny from all\n<FilesMatch \".*\">\nSetHandler none\nphp_flag engine off\n</FilesMatch>\n");
        @file_put_contents($d . '/index.php', '<?php // silencio');
    }
    return $d;
}

/** Quita el spam de un texto sin tocar lo demás: enlaces de spam, las marcas «xrv-» y los contenedores que se quedan vacíos. */
function planb_quitar_spam($v)
{
    $rx = planb_spam_regex();
    $host = preg_replace('/^www\./', '', strtolower((string)parse_url(home_url(), PHP_URL_HOST)));
    // Enlaces externos con palabras de spam en el texto o en la dirección
    $v = preg_replace_callback('/<a\s[^>]*>.*?<\/a>/is', function ($m) use ($rx, $host) {
        if (!preg_match('/href\s*=\s*["\']?\s*(https?:)?\/\/([^\/"\'\s>]+)/i', $m[0], $h)) return $m[0];
        $dom = preg_replace('/^www\./', '', strtolower($h[2]));
        if ($dom === $host || substr($dom, -strlen('.' . $host)) === '.' . $host) return $m[0];
        return preg_match($rx, $m[0]) ? '' : $m[0];
    }, $v);
    // Bloques escondidos (fuera de la pantalla o invisibles) con enlaces a otras webs: es la forma típica de meter spam
    $v = preg_replace_callback('/<(div|span|p|section)\b[^>]*style\s*=\s*["\'][^"\']*(left:\s*-\d{3,}px|top:\s*-\d{3,}px|display:\s*none|text-indent:\s*-\d{3,}|font-size:\s*0|height:\s*1px;\s*overflow:\s*hidden)[^"\']*["\'][^>]*>((?:(?!<\1\b).)*?)<\/\1>/is', function ($m) use ($host) {
        if (!preg_match_all('/href\s*=\s*["\']?\s*(https?:)?\/\/([^\/"\'\s>]+)/i', $m[3], $hh)) return stripos($m[3], 'xrv-') !== false ? '' : $m[0];
        foreach ($hh[2] as $d) { $d = preg_replace('/^www\./', '', strtolower($d)); if ($d !== $host && substr($d, -strlen('.' . $host)) !== '.' . $host) return ''; }
        return $m[0];
    }, $v);
    // Marcas de la campaña (comentarios, etiquetas vacías con data-xr y el texto xrv-)
    $v = preg_replace('/<!--\s*xr-verify-[0-9a-f]+\s*-->/i', '', $v);
    $v = preg_replace('/<(span|div)\b[^>]*data-xr(-verify)?=["\'][0-9a-f]+["\'][^>]*>\s*<\/\1>/i', '', $v);
    $v = preg_replace('/xrv-[0-9a-f]{6,}/i', '', $v);
    // Contenedores que han quedado vacíos (varias pasadas: los vacíos dentro de vacíos)
    for ($i = 0; $i < 6; $i++) {
        $antes = $v;
        $v = preg_replace('/<(div|span|p|li|ul|ol|section|small|font|center|nav|aside)(\s[^>]*)?>(\s|&nbsp;|,|\||·|-)*<\/\1>/i', '', $v);
        if ($v === $antes) break;
    }
    return $v;
}
function planb_quitar_spam_valor($v)
{
    if (is_array($v)) { foreach ($v as $k => $x) $v[$k] = planb_quitar_spam_valor($x); return $v; }
    if (is_object($v)) { foreach (get_object_vars($v) as $k => $x) $v->$k = planb_quitar_spam_valor($x); return $v; }
    return is_string($v) ? planb_quitar_spam($v) : $v;
}

function planb_cambiar_config($cambio)
{
    $ruta = is_file(ABSPATH . 'wp-config.php') ? ABSPATH . 'wp-config.php' : dirname(ABSPATH) . '/wp-config.php';
    $c = (string)@file_get_contents($ruta);
    if ($c === '' || !is_writable($ruta)) return 'no se puede escribir wp-config.php';
    $nuevo = call_user_func($cambio, $c);
    if (!is_string($nuevo) || $nuevo === $c) return 'sin cambios';
    // Comprobación mínima: sigue teniendo los datos de la base de datos y el final de WordPress
    if (strpos($nuevo, 'DB_NAME') === false || strpos($nuevo, 'wp-settings.php') === false) return 'cambio descartado (no parece un wp-config válido)';
    @copy($ruta, planb_dir_cuarentena() . '/wp-config-' . date('Ymd-His') . '.php.bak');
    return @file_put_contents($ruta, $nuevo) !== false ? 'ok' : 'no se pudo guardar';
}

/** ¿Arranca la web? Pide la portada y una página interna como un visitante (petición aparte, sin caché). */
function planb_web_arranca()
{
    foreach (array(home_url('/'), home_url('/?p=' . (int)get_option('page_on_front'))) as $i => $u) {
        $r = wp_remote_get(add_query_arg('pbcheck', time() . $i, $u), array('timeout' => 20, 'redirection' => 3, 'sslverify' => false, 'headers' => array('Cache-Control' => 'no-cache'))); // nosemgrep: tls-sin-verificar — la web se mira a sí misma
        if (is_wp_error($r)) return false;
        $c = (int)wp_remote_retrieve_response_code($r); $b = (string)wp_remote_retrieve_body($r);
        if ($c >= 500 || stripos($b, 'wp-die-message') !== false || stripos($b, 'error cr') !== false && stripos($b, 'WordPress') !== false && strlen($b) < 20000 || stripos($b, 'Fatal error') !== false) return false;
    }
    return true;
}

function planb_limpiar(WP_REST_Request $req)
{
    planb_cargar_admin();
    require_once ABSPATH . 'wp-admin/includes/user.php';
    global $wpdb, $wp_version;
    $p = (array)$req->get_json_params();
    $hecho = array(); $fallos = array();
    $marca = date('Ymd-His');
    $cuarentena = planb_dir_cuarentena() . '/' . $marca;
    $deshacer = array('archivos' => array(), 'bd' => array());

    // 1 · Archivos a cuarentena (no se borran): se mueven y se les cambia la extensión para que no se puedan ejecutar
    foreach ((array)(isset($p['archivos']) ? $p['archivos'] : array()) as $rel) {
        $rel = ltrim(str_replace('\\', '/', (string)$rel), '/');
        if ($rel === '' || strpos($rel, '..') !== false) continue;
        $abs = ABSPATH . $rel;
        if (!is_file($abs) || in_array($rel, array('wp-config.php', 'index.php', 'wp-settings.php', 'wp-load.php'), true) || strpos($rel, 'planb-conector') !== false) { $fallos[] = 'No se mueve ' . $rel; continue; }
        $dest = $cuarentena . '/' . $rel . '.bloqueado';
        wp_mkdir_p(dirname($dest));
        if (@rename($abs, $dest)) {
            // Comprobación inmediata: si sin este archivo la web deja de arrancar, era necesario y se devuelve a su sitio
            if (!planb_web_arranca()) { @rename($dest, $abs); $fallos[] = 'No se mueve ' . $rel . ': sin él la web deja de funcionar (es un archivo necesario, se ha devuelto)'; continue; }
            $hecho[] = 'Cuarentena: ' . $rel; $deshacer['archivos'][] = array($rel, $dest);
        }
        else $fallos[] = 'No se pudo mover ' . $rel;
    }

    // 2 · Base de datos: se quita solo el spam y se guarda el valor anterior
    $permitidas = $wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($wpdb->prefix) . '%'));
    foreach ((array)(isset($p['bd']) ? $p['bd'] : array()) as $x) {
        $t = (string)$x['tabla']; $pk = (string)$x['pk']; $col = (string)$x['columna']; $id = (string)$x['id'];
        if (!in_array($t, $permitidas, true) || !preg_match('/^\w+$/', $pk) || !preg_match('/^\w+$/', $col)) continue;
        $v = $wpdb->get_var($wpdb->prepare('SELECT `' . $col . '` FROM `' . $t . '` WHERE `' . $pk . '`=%s', $id));
        if ($v === null) continue;
        if (!empty($x['borrar']) && $t === $wpdb->options) {
            // Cachés (transients) con spam: se borran, WordPress las vuelve a crear limpias
            $deshacer['bd'][] = array($t, $pk, $id, $col, $v, 'fila', (string)$wpdb->get_var($wpdb->prepare('SELECT option_name FROM `' . $t . '` WHERE `' . $pk . '`=%s', $id)));
            $wpdb->delete($t, array($pk => $id));
            $hecho[] = 'Caché borrada: ' . (isset($x['nombre']) ? $x['nombre'] : $id);
            continue;
        }
        if (is_serialized($v)) { $u = planb_unserialize_seguro($v); $nuevo = $u === false ? $v : serialize(planb_quitar_spam_valor($u)); }
        else $nuevo = planb_quitar_spam($v);
        if ($nuevo === $v && $t === $wpdb->postmeta && !preg_match('/<|\s/', (string)$v)) {
            // 1.7.15 (Jesús, 24/11/2026): restos de las entradas de spam (el nombre de su dirección, que WordPress guarda al
            // mandarlas a la papelera, o el nombre de una imagen de casino). No llevan enlaces, así que no hay nada que
            // «quitar»: se borra la línea entera. Solo si es un dato de una palabra (sin espacios ni HTML) y su entrada está
            // en la papelera, es de spam o es una imagen de spam. Se guarda la línea entera para poder deshacerlo.
            $fm = $wpdb->get_row($wpdb->prepare('SELECT * FROM `' . $t . '` WHERE meta_id=%d', $id), ARRAY_A);
            $post = $fm ? get_post((int)$fm['post_id']) : null;
            $resto = $fm && (in_array($fm['meta_key'], array('_wp_desired_post_slug', '_wp_old_slug', '_wp_trash_meta_status', '_wp_trash_meta_time'), true)
                || !$post || $post->post_status === 'trash' || ($post->post_type === 'attachment' && preg_match(planb_spam_regex(), $post->post_title . ' ' . $post->post_name)));
            if ($resto) {
                $deshacer['bd'][] = array($t, 'meta_id', $id, 'meta_value', $v, 'filameta', $fm);
                $wpdb->delete($t, array('meta_id' => (int)$id));
                $hecho[] = 'Resto de spam borrado: ' . $fm['meta_key'] . ' = ' . mb_substr((string)$v, 0, 60);
                continue;
            }
        }
        if ($nuevo === $v) { $fallos[] = 'Sin cambios en ' . $t . ' #' . $id . ' (hay que mirarlo a mano)'; continue; }
        // Seguro: si se quitase más de la mitad del contenido normal, no se toca (puede que no sea solo spam)
        $limpioAntes = strlen(strip_tags(preg_replace('/<a\s[^>]*>.*?<\/a>/is', '', $v)));
        $limpioDespues = strlen(strip_tags(preg_replace('/<a\s[^>]*>.*?<\/a>/is', '', $nuevo)));
        if ($limpioAntes > 400 && $limpioDespues < $limpioAntes * 0.5) { $fallos[] = 'No se toca ' . $t . ' #' . $id . ': se iría demasiado contenido (revisar a mano)'; continue; }
        $deshacer['bd'][] = array($t, $pk, $id, $col, $v, 'valor');
        $wpdb->update($t, array($col => $nuevo), array($pk => $id));
        $hecho[] = 'Spam quitado: ' . (isset($x['nombre']) && $x['nombre'] !== '' ? $x['nombre'] : $t . ' #' . $id) . ' (' . (strlen($v) - strlen($nuevo)) . ' caracteres menos)';
        if ($t === $wpdb->posts) clean_post_cache((int)$id);
    }

    // 2a · Páginas que vuelven a su versión de antes del hackeo (el historial de revisiones de WordPress)
    foreach (array_map('intval', (array)(isset($p['revisiones']) ? $p['revisiones'] : array())) as $pid) {
        $post = get_post($pid);
        if (!$post) continue;
        $rx2 = planb_spam_regex();
        $buena = null; $vistas = 0;
        foreach (wp_get_post_revisions($pid, array('order' => 'DESC', 'orderby' => 'date ID')) as $rev) {
            $vistas++;
            if (!preg_match($rx2, $rev->post_content) && strlen(trim($rev->post_content)) > 200) { $buena = $rev; break; }
        }
        if (!$buena) { $fallos[] = $post->post_title . ': no hay ninguna versión anterior limpia (' . $vistas . ' revisadas)'; continue; }
        $deshacer['bd'][] = array($wpdb->posts, 'ID', (string)$pid, 'post_content', $post->post_content, 'valor');
        wp_restore_post_revision($buena->ID);
        clean_post_cache($pid);
        $hecho[] = $post->post_title . ': vuelta a la versión del ' . mysql2date('d/m/Y H:i', $buena->post_modified) . ' (antes del hackeo)';
    }

    // 2b · Entradas de spam a la papelera de WordPress (se pueden recuperar desde Entradas → Papelera)
    $papelera = array_map('intval', (array)(isset($p['papelera']) ? $p['papelera'] : array()));
    if ($papelera) {
        $n = 0;
        $t0p = microtime(true); foreach ($papelera as $pid) { if (microtime(true) - $t0p > 25) break; if ($pid > 0 && $pid !== (int)get_option('page_on_front') && wp_trash_post($pid)) $n++; }
        $hecho[] = $n . ' entradas de spam enviadas a la papelera de WordPress';
    }

    // 2b2 · TODAS las entradas del blog a la papelera de golpe (webs sin blog propio: todo lo que hay es del hackeo).
    // Se hace con la base de datos directamente (decenas de miles en segundos) y con las marcas de WordPress para poder recuperarlas.
    if (!empty($p['papelera_blog'])) {
        $t = time();
        $wpdb->query("INSERT INTO {$wpdb->postmeta} (post_id, meta_key, meta_value) SELECT ID, '_wp_trash_meta_status', post_status FROM {$wpdb->posts} WHERE post_type='post' AND post_status NOT IN ('trash','auto-draft','inherit')");
        $wpdb->query($wpdb->prepare("INSERT INTO {$wpdb->postmeta} (post_id, meta_key, meta_value) SELECT ID, '_wp_trash_meta_time', %s FROM {$wpdb->posts} WHERE post_type='post' AND post_status NOT IN ('trash','auto-draft','inherit')", (string)$t));
        $n = (int)$wpdb->query("UPDATE {$wpdb->posts} SET post_status='trash' WHERE post_type='post' AND post_status NOT IN ('trash','auto-draft','inherit')");
        // Los comentarios de esas entradas también fuera, y las categorías y etiquetas de spam dejan de contar
        $wpdb->query("UPDATE {$wpdb->comments} c JOIN {$wpdb->posts} p ON p.ID=c.comment_post_ID SET c.comment_approved='post-trashed' WHERE p.post_type='post' AND p.post_status='trash' AND c.comment_approved IN ('0','1')");
        $wpdb->query("UPDATE {$wpdb->term_taxonomy} tt SET tt.count=(SELECT COUNT(*) FROM {$wpdb->term_relationships} tr JOIN {$wpdb->posts} p ON p.ID=tr.object_id WHERE tr.term_taxonomy_id=tt.term_taxonomy_id AND p.post_status='publish') WHERE tt.taxonomy IN ('category','post_tag')");
        wp_cache_flush();
        $hecho[] = $n . ' entradas del blog enviadas a la papelera de golpe';
    }

    // 2c · Usuarios que publican spam: todo lo suyo a la papelera (por tandas) y el usuario fuera (sin borrar nada más)
    foreach (array_map('intval', (array)(isset($p['autores']) ? $p['autores'] : array())) as $uid) {
        $u = get_userdata($uid);
        if (!$u || in_array('administrator', (array)$u->roles, true) && count(get_users(array('role' => 'administrator', 'fields' => 'ID'))) < 2) { $fallos[] = 'No se quita el usuario ' . $uid . ' (es el único administrador)'; continue; }
        $ids = $wpdb->get_col($wpdb->prepare("SELECT ID FROM {$wpdb->posts} WHERE post_author=%d AND post_status NOT IN ('trash','auto-draft') AND post_type NOT IN ('revision','nav_menu_item') LIMIT 400", $uid));
        $n = 0; $t0a = microtime(true); foreach ($ids as $pid) { if (microtime(true) - $t0a > 25) break; if ((int)$pid !== (int)get_option('page_on_front') && wp_trash_post((int)$pid)) $n++; }
        $quedan = (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_author=%d AND post_status NOT IN ('trash','auto-draft') AND post_type NOT IN ('revision','nav_menu_item')", $uid));
        if ($quedan === 0) {
            // Se le quita todo el acceso: sin rol y con una contraseña nueva que nadie sabe
            $u->set_role('');
            wp_set_password(wp_generate_password(40, true, true), $uid);
            if (class_exists('WP_Application_Passwords')) WP_Application_Passwords::delete_all_application_passwords($uid);
            $hecho[] = 'Usuario ' . $u->user_login . ': ' . $n . ' entradas a la papelera y sin acceso';
        } else $hecho[] = 'Usuario ' . $u->user_login . ': ' . $n . ' entradas a la papelera (quedan ' . $quedan . ', otra pasada)';
    }
    // 2d · Cerrar las puertas de publicación a distancia
    if (!empty($p['cerrar_remoto'])) { update_option('planb_sin_xmlrpc', 1, true); $hecho[] = 'XML-RPC y contraseñas de aplicación desactivados (no se puede publicar a distancia)'; }

    // 3 · Plugins de wordpress.org reinstalados desde los oficiales (misma versión: la web no cambia)
    foreach ((array)(isset($p['reinstalar_plugins']) ? $p['reinstalar_plugins'] : array()) as $x) {
        $slug = sanitize_key((string)$x['slug']); $ver = preg_replace('/[^0-9a-zA-Z.\-]/', '', (string)$x['version']);
        if ($slug === '' || $ver === '') continue;
        $up = new Plugin_Upgrader(new Planb_Piel_Silenciosa());
        $r = $up->install('https://downloads.wordpress.org/plugin/' . $slug . '.' . $ver . '.zip', array('overwrite_package' => true, 'clear_update_cache' => false));
        if ($r === true) $hecho[] = 'Plugin reinstalado limpio: ' . $slug . ' ' . $ver; else $fallos[] = 'No se pudo reinstalar ' . $slug . (is_wp_error($r) ? ': ' . $r->get_error_message() : '');
    }

    // 4 · WordPress reinstalado desde el oficial (misma versión)
    if (!empty($p['reinstalar_core'])) {
        $loc = get_locale();
        $url = $loc && $loc !== 'en_US' ? 'https://downloads.wordpress.org/release/' . $loc . '/wordpress-' . $wp_version . '.zip' : 'https://downloads.wordpress.org/release/wordpress-' . $wp_version . '.zip';
        $prueba = wp_remote_head($url, array('timeout' => 15));
        if (is_wp_error($prueba) || wp_remote_retrieve_response_code($prueba) !== 200) { $url = 'https://downloads.wordpress.org/release/wordpress-' . $wp_version . '.zip'; $loc = 'en_US'; }
        $oferta = (object)array('response' => 'reinstall', 'download' => $url, 'locale' => $loc, 'current' => $wp_version, 'version' => $wp_version, 'php_version' => '5.6', 'mysql_version' => '5.0', 'new_bundled' => '', 'partial_version' => '',
            'packages' => (object)array('full' => $url, 'no_content' => '', 'new_bundled' => '', 'partial' => false, 'rollback' => false));
        $up = new Core_Upgrader(new Planb_Piel_Silenciosa());
        $r = $up->upgrade($oferta, array('attempt_rollback' => false));
        if (is_wp_error($r)) $fallos[] = 'WordPress no se pudo reinstalar: ' . $r->get_error_message(); else $hecho[] = 'WordPress ' . $wp_version . ' reinstalado desde el oficial';
    }

    // 5 · Administradores que no se reconocen (sus entradas pasan al primer administrador que se queda)
    $quitar = array_map('strval', (array)(isset($p['quitar_admins']) ? $p['quitar_admins'] : array()));
    if ($quitar) {
        $quedan = array();
        foreach (get_users(array('role__in' => array('administrator'), 'fields' => array('ID', 'user_login'))) as $u) if (!in_array($u->user_login, $quitar, true)) $quedan[] = (int)$u->ID;
        if (!$quedan) $fallos[] = 'No se quitan administradores: no quedaría ninguno';
        else foreach ($quitar as $login) {
            $u = get_user_by('login', $login);
            if (!$u) continue;
            if (wp_delete_user($u->ID, $quedan[0])) $hecho[] = 'Administrador quitado: ' . $login; else $fallos[] = 'No se pudo quitar ' . $login;
        }
    }

    // 6 · Registro cerrado y rol por defecto seguro
    if (!empty($p['cerrar_registro'])) { update_option('users_can_register', 0); if (get_option('default_role') !== 'subscriber') update_option('default_role', 'subscriber'); $hecho[] = 'Registro cerrado y rol por defecto: suscriptor'; }

    // 7 · Errores ocultos al público (el conector carga antes que el resto de plugins y los oculta)
    if (!empty($p['ocultar_errores'])) {
        update_option('planb_ocultar_errores', 1, true);
        $r = planb_cambiar_config(function ($c) { return preg_replace("/define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)/i", "define('WP_DEBUG', false)", $c); });
        $hecho[] = 'Errores ocultos al público' . ($r === 'ok' ? ' (y WP_DEBUG desactivado)' : '');
    }

    // 8 · Claves secretas nuevas: cierra las sesiones de cualquiera que hubiera entrado
    if (!empty($p['claves'])) {
        $r = planb_cambiar_config(function ($c) {
            $n = 0;
            foreach (array('AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT') as $k) {
                $nueva = str_replace(array("'", '\\'), array('x', 'y'), wp_generate_password(64, true, true));
                $c = preg_replace("/define\s*\(\s*['\"]" . $k . "['\"]\s*,\s*(['\"]).*?\\1\s*\)/s", "define('" . $k . "', '" . $nueva . "')", $c, 1, $cuenta);
                $n += $cuenta;
            }
            return $n === 8 ? $c : null;
        });
        if ($r === 'ok') $hecho[] = 'Claves secretas nuevas (se ha cerrado la sesión de todo el mundo)'; else $fallos[] = 'Claves secretas: ' . $r;
    }

    // Lo necesario para deshacer (los archivos siguen en la cuarentena)
    update_option('planb_limpieza_' . $marca, $deshacer, false);
    if (function_exists('wp_cache_flush')) wp_cache_flush();
    return array('hecho' => $hecho, 'fallos' => $fallos, 'marca' => $marca);
}

/** Deshace una limpieza: devuelve los archivos y los valores de la base de datos. */
function planb_deshacer_limpieza(WP_REST_Request $req)
{
    global $wpdb;
    $p = (array)$req->get_json_params();
    $marca = preg_replace('/[^0-9\-]/', '', (string)(isset($p['marca']) ? $p['marca'] : ''));
    $d = get_option('planb_limpieza_' . $marca);
    if (!is_array($d)) return new WP_Error('no', 'No hay nada que deshacer', array('status' => 404));
    $n = 0;
    foreach ($d['archivos'] as $a) { wp_mkdir_p(dirname(ABSPATH . $a[0])); if (@rename($a[1], ABSPATH . $a[0])) $n++; }
    foreach ($d['bd'] as $x) {
        if ($x[5] === 'filameta' && is_array($x[6])) $wpdb->insert($x[0], $x[6]); // línea de postmeta borrada entera: vuelve tal cual
        elseif ($x[5] === 'fila') $wpdb->insert($x[0], array($x[1] => $x[2], $x[3] => $x[4], 'option_name' => isset($x[6]) && $x[6] !== '' ? $x[6] : 'planb_recuperada_' . $x[2], 'autoload' => 'no'));
        else $wpdb->update($x[0], array($x[3] => $x[4]), array($x[1] => $x[2]));
        $n++;
    }
    delete_option('planb_limpieza_' . $marca);
    return array('deshecho' => $n);
}

/** Borra de verdad lo que está en cuarentena (cuando ya se ha comprobado que la web va bien). */
function planb_vaciar_cuarentena(WP_REST_Request $req)
{
    $d = WP_CONTENT_DIR . '/planb-cuarentena';
    $n = 0;
    if (is_dir($d)) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $b = $f->getFilename();
            if ($f->getPath() === $d && in_array($b, array('.htaccess', 'index.php'), true)) continue;
            if ($f->isDir()) @rmdir($f->getPathname()); elseif (@unlink($f->getPathname())) $n++;
        }
    }
    global $wpdb;
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'planb\\_limpieza\\_%'");
    return array('borrados' => $n);
}


/* ───────────── Tildes rotas (texto UTF-8 guardado dos veces: «AuditorÃ­as» en vez de «Auditorías») ───────────── */
function planb_tildes_rx()
{
    $c = '[\x{0080}-\x{00BF}\x{0152}\x{0153}\x{0160}\x{0161}\x{0178}\x{017D}\x{017E}\x{0192}\x{02C6}\x{02DC}\x{2013}\x{2014}\x{2018}-\x{201E}\x{2020}-\x{2022}\x{2026}\x{2030}\x{2039}\x{203A}\x{20AC}\x{2122}]';
    return '/(?:[\x{00C2}\x{00C3}]' . $c . '|\x{00E2}' . $c . $c . ')+/u';
}
function planb_arreglar_tildes($v)
{
    if (is_array($v)) { foreach ($v as $k => $x) $v[$k] = planb_arreglar_tildes($x); return $v; }
    if (is_object($v)) { foreach (get_object_vars($v) as $k => $x) $v->$k = planb_arreglar_tildes($x); return $v; }
    if (!is_string($v) || $v === '') return $v;
    $r = @preg_replace_callback(planb_tildes_rx(), function ($m) {
        // Cada letra vuelve a ser el byte que era: las de 0-255 tal cual y las de Windows-1252 (€, —, “…) con su tabla.
        // Así también se arreglan los textos con caracteres de control invisibles (los «cuadraditos»).
        $tabla = array(0x20AC => 0x80, 0x201A => 0x82, 0x0192 => 0x83, 0x201E => 0x84, 0x2026 => 0x85, 0x2020 => 0x86, 0x2021 => 0x87, 0x02C6 => 0x88, 0x2030 => 0x89, 0x0160 => 0x8A, 0x2039 => 0x8B, 0x0152 => 0x8C, 0x017D => 0x8E,
            0x2018 => 0x91, 0x2019 => 0x92, 0x201C => 0x93, 0x201D => 0x94, 0x2022 => 0x95, 0x2013 => 0x96, 0x2014 => 0x97, 0x02DC => 0x98, 0x2122 => 0x99, 0x0161 => 0x9A, 0x203A => 0x9B, 0x0153 => 0x9C, 0x017E => 0x9E, 0x0178 => 0x9F);
        $b = '';
        foreach (preg_split('//u', $m[0], -1, PREG_SPLIT_NO_EMPTY) as $ch) {
            $cp = function_exists('mb_ord') ? mb_ord($ch, 'UTF-8') : (int)hexdec(bin2hex(mb_convert_encoding($ch, 'UCS-4BE', 'UTF-8')));
            if ($cp <= 0xFF) $b .= chr($cp); elseif (isset($tabla[$cp])) $b .= chr($tabla[$cp]); else return $m[0];
        }
        return $b !== '' && mb_check_encoding($b, 'UTF-8') ? $b : $m[0];
    }, $v);
    if (!is_string($r)) $r = $v;
    // Textos guardados como JSON (p. ej. el slider): «Ã­» aparece escrito como \u00c3\u00ad
    if (preg_match('/\\\\u00(c[23]|e2)/i', $r)) {
        $r2 = @preg_replace_callback('/(?:\\\\u00c[23]\\\\u00[89ab][0-9a-f]|\\\\u00e2\\\\u00[89ab][0-9a-f]\\\\u00[89ab][0-9a-f])+/i', function ($m) {
            $t = json_decode('"' . $m[0] . '"');
            if (!is_string($t)) return $m[0];
            $f = @mb_convert_encoding($t, 'ISO-8859-1', 'UTF-8');
            if (!is_string($f) || !mb_check_encoding($f, 'UTF-8') || $f === $t) return $m[0];
            $j = json_encode($f);
            return is_string($j) ? substr($j, 1, -1) : $m[0];
        }, $r);
        if (is_string($r2)) $r = $r2;
    }
    return $r;
}
/** Filas con tildes rotas: [tabla, pk, id, columna] (las del registro de visitas no). */
function planb_filas_tildes($max, $desde = null, $tope = 0)
{
    // $desde = array(tabla, columna, id): se sigue a partir de ahí (para ir por tandas sin repasar lo ya visto)
    // $tope: segundos máximos buscando (0 = sin tope)
    global $wpdb;
    $o = array(); $t0 = microtime(true); $pasado = $desde === null;
    $tablas = $wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($wpdb->prefix) . '%'));
    sort($tablas);
    foreach ($tablas as $t) {
        if (preg_match('/(_events|_log|_logs|_audit|_activity|_stats|_visits?|_404|wfhits|wflogs|_sessions|actionscheduler)/i', substr($t, strlen($wpdb->prefix)))) continue;
        if (!$pasado && $t !== $desde[0] && strcmp($t, $desde[0]) < 0) continue;
        $pk = null; $txt = array(); $numerica = false;
        foreach ($wpdb->get_results('SHOW COLUMNS FROM `' . esc_sql($t) . '`', ARRAY_A) as $c) {
            if ($c['Key'] === 'PRI' && $pk === null) { $pk = $c['Field']; $numerica = (bool)preg_match('/int/i', $c['Type']); }
            if (preg_match('/text|char/i', $c['Type'])) $txt[] = $c['Field'];
        }
        if (!$pk || !$txt) continue;
        sort($txt);
        foreach ($txt as $c) {
            $despues = '';
            if (!$pasado) {
                if ($t === $desde[0] && strcmp($c, $desde[1]) < 0) continue;
                if ($t === $desde[0] && $c === $desde[1]) $despues = ' AND `' . esc_sql($pk) . '` > ' . ($numerica ? (int)$desde[2] : $wpdb->prepare('%s', (string)$desde[2]));
                $pasado = true;
            }
            if ($tope && microtime(true) - $t0 > $tope) { if (!$o) $GLOBALS['planb_tildes_sigue'] = array($t, $c, $numerica ? -1 : ''); return $o; }
            // Comparación por bytes: con la comparación normal «Ã» sería igual que «a». Lo que está en la papelera (el spam) no se toca
            $extra = $t === $wpdb->posts ? " AND post_status<>'trash'" : ($t === $wpdb->postmeta ? " AND NOT EXISTS (SELECT 1 FROM {$wpdb->posts} pz WHERE pz.ID=post_id AND pz.post_status='trash')" : '');
            $json = $wpdb->prepare('%s', '%' . $wpdb->esc_like('\\u00c3\\u00') . '%');
            $ids = $wpdb->get_col("SELECT `" . esc_sql($pk) . "` FROM `" . esc_sql($t) . "` WHERE (BINARY `" . esc_sql($c) . "` LIKE BINARY '%Ã%' OR BINARY `" . esc_sql($c) . "` LIKE BINARY '%â€%' OR BINARY `" . esc_sql($c) . "` LIKE BINARY '%Â%' OR `" . esc_sql($c) . "` LIKE " . $json . ")" . $extra . $despues . " ORDER BY `" . esc_sql($pk) . "` LIMIT " . (int)$max);
            foreach ($ids as $id) { $o[] = array($t, $pk, (string)$id, $c); if (count($o) >= $max) return $o; }
        }
    }
    return $o;
}

/** Trabajos por tandas (para servidores que cortan las peticiones largas). Devuelven cuántos quedan. */
function planb_tanda(WP_REST_Request $req)
{
    @set_time_limit(60);
    global $wpdb;
    $p = (array)$req->get_json_params();
    $que = (string)(isset($p['que']) ? $p['que'] : '');
    $t0 = microtime(true);
    $hecho = 0;
    if ($que === 'tildes') {
        // Por tandas con marcador: cada tanda sigue donde se quedó la anterior (lo que no se puede arreglar no se vuelve a mirar)
        $deshacer = (array)get_option('planb_tildes_copia', array());
        $cursor = get_option('planb_tildes_cursor', null);
        $filas = planb_filas_tildes(60, is_array($cursor) ? $cursor : null, 15);
        $vistas = 0;
        foreach ($filas as $f) {
            if (microtime(true) - $t0 > 25) break;
            list($t, $pk, $id, $col) = $f;
            $vistas++; $cursor = array($t, $col, $id);
            $v = $wpdb->get_var($wpdb->prepare('SELECT `' . $col . '` FROM `' . $t . '` WHERE `' . $pk . '`=%s', $id));
            if ($v === null) continue;
            if (is_serialized($v)) { $u = planb_unserialize_seguro($v); $nuevo = $u === false ? $v : serialize(planb_arreglar_tildes($u)); }
            else $nuevo = planb_arreglar_tildes($v);
            if ($nuevo === $v) continue;
            if (count($deshacer) < 5000) $deshacer[] = array($t, $pk, $id, $col, $v);
            $wpdb->update($t, array($col => $nuevo), array($pk => $id));
            $hecho++;
        }
        update_option('planb_tildes_copia', $deshacer, false);
        wp_cache_flush();
        // Si no ha salido ninguna fila más, se ha terminado el repaso: se borra el marcador
        if (!$filas && !empty($GLOBALS['planb_tildes_sigue'])) { update_option('planb_tildes_cursor', $GLOBALS['planb_tildes_sigue'], false); return array('hecho' => 0, 'quedan' => 1, 'avance' => 1); }
        if (!$filas) { delete_option('planb_tildes_cursor'); return array('hecho' => $hecho, 'quedan' => 0, 'avance' => 0); }
        update_option('planb_tildes_cursor', $cursor, false);
        return array('hecho' => $hecho, 'quedan' => max(1, count($filas) - $vistas + 1), 'avance' => $vistas);
    }
    if ($que === 'porcentajes') {
        // Reparación: datos restaurados de un punto antiguo con el «%» guardado como {hash de 64} (rompe textos y datos serializados)
        $quedan = 0;
        foreach ($wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($wpdb->prefix) . '%')) as $t) {
            $pk = null; $txt = array();
            foreach ($wpdb->get_results('SHOW COLUMNS FROM `' . esc_sql($t) . '`', ARRAY_A) as $c) { if ($c['Key'] === 'PRI' && $pk === null) $pk = $c['Field']; if (preg_match('/text|char/i', $c['Type'])) $txt[] = $c['Field']; }
            if (!$pk) continue;
            foreach ($txt as $c) {
                if (microtime(true) - $t0 > 20) { $quedan++; break 2; }
                $filas = $wpdb->get_results('SELECT `' . esc_sql($pk) . '` k, `' . esc_sql($c) . "` v FROM `" . esc_sql($t) . '` WHERE `' . esc_sql($c) . "` REGEXP '[{][0-9a-f]{64}[}]' LIMIT 300", ARRAY_A);
                foreach ((array)$filas as $f) {
                    $nuevo = preg_replace('/\{[0-9a-f]{64}\}/', '%', (string)$f['v']);
                    if ($nuevo !== $f['v']) { $wpdb->update($t, array($c => $nuevo), array($pk => $f['k'])); $hecho++; }
                }
                if (count((array)$filas) === 300) $quedan++;
            }
        }
        wp_cache_flush();
        return array('hecho' => $hecho, 'quedan' => $quedan);
    }
    if ($que === 'adjuntos') {
        // Imágenes del spam: colgaban de entradas que están en la papelera, o tienen nombre de casino; nunca las que usa una página
        $rx = planb_spam_regex();
        $ids = $wpdb->get_col("SELECT a.ID FROM {$wpdb->posts} a LEFT JOIN {$wpdb->posts} p ON p.ID=a.post_parent WHERE a.post_type='attachment' AND ((p.ID IS NOT NULL AND p.post_type='post' AND p.post_status='trash') OR a.post_title REGEXP 'casino|kasyn|bet|slot|bonus|roulette|poker|aviator|pin-?up' OR a.guid REGEXP 'casino|kasyn|slot|bonus|roulette|poker|aviator|pin-?up') LIMIT 400");
        $saltadas = 0;
        foreach ($ids as $id) {
            if (microtime(true) - $t0 > 15) break;
            $f = (string)get_post_meta((int)$id, '_wp_attached_file', true);
            $base = $f !== '' ? pathinfo($f, PATHINFO_FILENAME) : '';
            $usada = $base !== '' && (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status IN ('publish','private','draft','future') AND post_type NOT IN ('post','attachment','revision') AND post_content LIKE %s", '%' . $wpdb->esc_like($base) . '%'));
            $usada = $usada || (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->postmeta} m JOIN {$wpdb->posts} p ON p.ID=m.post_id WHERE m.meta_key='_thumbnail_id' AND m.meta_value=%s AND p.post_type<>'post'", (string)$id));
            if ($usada) { $saltadas++; update_post_meta((int)$id, '_planb_no_tocar', 1); continue; }
            if (wp_delete_attachment((int)$id, true)) $hecho++;
        }
        $quedan = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} a LEFT JOIN {$wpdb->posts} p ON p.ID=a.post_parent LEFT JOIN {$wpdb->postmeta} nt ON nt.post_id=a.ID AND nt.meta_key='_planb_no_tocar' WHERE nt.meta_id IS NULL AND a.post_type='attachment' AND ((p.ID IS NOT NULL AND p.post_type='post' AND p.post_status='trash') OR a.post_title REGEXP 'casino|kasyn|bet|slot|bonus|roulette|poker|aviator|pin-?up' OR a.guid REGEXP 'casino|kasyn|slot|bonus|roulette|poker|aviator|pin-?up')");
        return array('hecho' => $hecho, 'quedan' => $quedan, 'saltadas' => $saltadas);
    }
    if ($que === 'papelera') {
        // Borra para siempre las ENTRADAS (no páginas) que están en la papelera: el spam que ya se mandó allí. Por tandas de 300.
        $ids = array_map('intval', $wpdb->get_col("SELECT ID FROM {$wpdb->posts} WHERE post_type='post' AND post_status='trash' LIMIT 300"));
        if ($ids) {
            $in = implode(',', $ids);
            $wpdb->query("DELETE FROM {$wpdb->postmeta} WHERE post_id IN ($in)");
            $wpdb->query("DELETE FROM {$wpdb->term_relationships} WHERE object_id IN ($in)");
            $wpdb->query("DELETE cm FROM {$wpdb->commentmeta} cm JOIN {$wpdb->comments} c ON c.comment_ID=cm.comment_id WHERE c.comment_post_ID IN ($in)");
            $wpdb->query("DELETE FROM {$wpdb->comments} WHERE comment_post_ID IN ($in)");
            // Sus revisiones y adjuntos de spam también fuera
            $wpdb->query("DELETE FROM {$wpdb->posts} WHERE post_type='revision' AND post_parent IN ($in)");
            $hecho = (int)$wpdb->query("DELETE FROM {$wpdb->posts} WHERE ID IN ($in) AND post_type='post' AND post_status='trash'");
        }
        wp_cache_flush();
        return array('hecho' => $hecho, 'quedan' => (int)$wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type='post' AND post_status='trash'"));
    }
    if ($que === 'terminos') {
        // Categorías y etiquetas sin ninguna entrada publicada (las del spam); la categoría por defecto se queda
        $def = (int)get_option('default_category');
        $tts = $wpdb->get_results("SELECT tt.term_id, tt.taxonomy FROM {$wpdb->term_taxonomy} tt WHERE tt.taxonomy IN ('category','post_tag') AND tt.term_id<>" . $def . " AND NOT EXISTS (SELECT 1 FROM {$wpdb->term_relationships} tr JOIN {$wpdb->posts} p ON p.ID=tr.object_id WHERE tr.term_taxonomy_id=tt.term_taxonomy_id AND p.post_status IN ('publish','future','draft','private')) LIMIT 500");
        foreach ($tts as $x) { if (microtime(true) - $t0 > 15) break; if (!is_wp_error(wp_delete_term((int)$x->term_id, $x->taxonomy))) $hecho++; }
        $quedan = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->term_taxonomy} tt WHERE tt.taxonomy IN ('category','post_tag') AND tt.term_id<>" . $def . " AND NOT EXISTS (SELECT 1 FROM {$wpdb->term_relationships} tr JOIN {$wpdb->posts} p ON p.ID=tr.object_id WHERE tr.term_taxonomy_id=tt.term_taxonomy_id AND p.post_status IN ('publish','future','draft','private'))");
        return array('hecho' => $hecho, 'quedan' => $quedan);
    }
    if ($que === 'tildes_deshacer') {
        foreach ((array)get_option('planb_tildes_copia', array()) as $x) { $wpdb->update($x[0], array($x[3] => $x[4]), array($x[1] => $x[2])); $hecho++; }
        delete_option('planb_tildes_copia');
        return array('hecho' => $hecho, 'quedan' => 0);
    }
    return new WP_Error('que', 'Trabajo desconocido', array('status' => 400));
}
