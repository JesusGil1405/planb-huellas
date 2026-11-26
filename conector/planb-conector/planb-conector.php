<?php
/**
 * Plugin Name: Plan B Conector
 * Description: Conecta esta web con el Panel Plan B para el mantenimiento automático (estado, puntos de restauración, actualizaciones y clones de prueba).
 * Version: 1.7.37
 * Author: Plan B Ecommerce
 * Requires PHP: 5.6
 * License: Propietaria
 */
// Escrito compatible con PHP 5.6 a 8.5: debe funcionar también en las webs antiguas que hay que actualizar.

if (!defined('ABSPATH')) exit;

define('PLANB_CONECTOR_VERSION', '1.7.37');
if (!defined('PLANB_PANEL_URL')) define('PLANB_PANEL_URL', '__PANEL_URL__');
if (!defined('PLANB_CLAVE_REGISTRO')) define('PLANB_CLAVE_REGISTRO', '__CLAVE_REGISTRO__');
// 1.7.21 (auditoría): clave de alta de UN SOLO USO, propia de cada descarga. Las actualizaciones no llevan ninguna clave de alta:
// una web ya conectada se identifica con su propio secreto (y, si lo cambia, firmando con el anterior).
if (!defined('PLANB_TOKEN_ALTA')) define('PLANB_TOKEN_ALTA', '__TOKEN_ALTA__');
if (is_file(dirname(__FILE__) . '/limpieza.php')) require_once dirname(__FILE__) . '/limpieza.php';
// 1.7.37: restauración segura y candado de trabajos (compartido con rescate.php)
if (!defined('PLANB_RESTAURAR_LIB')) define('PLANB_RESTAURAR_LIB', 1);
if (is_file(dirname(__FILE__) . '/restaurar.php')) require_once dirname(__FILE__) . '/restaurar.php';
// Tras una limpieza: los errores de PHP no se enseñan al público (este plugin carga antes que el resto)
if (get_option('planb_ocultar_errores')) { @ini_set('display_errors', '0'); }
// Tras una limpieza: nadie puede publicar a distancia (XML-RPC ni contraseñas de aplicación). El panel usa su propia vía firmada.
if (get_option('planb_sin_xmlrpc')) { add_filter('xmlrpc_enabled', '__return_false'); add_filter('wp_is_application_passwords_available', '__return_false'); }

/*
 * ESCUDO (1.7.18 · Jesús, 24/11/2026, como el «Patch & Protect» de Modular DS). Para un plugin con un fallo grave y SIN versión
 * que lo arregle, sin desactivarlo: los VISITANTES SIN SESIÓN no pueden llamar a sus rutas de la API (wp-json), a sus acciones
 * AJAX ni abrir sus archivos .php directamente. La web se sigue viendo igual y quien ha entrado en WordPress lo usa normal.
 * Se quita solo en cuanto el plugin pasa de la versión con el fallo (o desde el panel).
 * planb_escudo = array(slug => array('version' => versión con el fallo, 'desde' => fecha))
 */
function planb_escudo_activos()
{
    $e = get_option('planb_escudo');
    if (!is_array($e) || !$e) return array();
    if (!function_exists('get_plugins')) @include_once ABSPATH . 'wp-admin/includes/plugin.php';
    $vers = array();
    if (function_exists('get_plugins')) foreach ((array)get_plugins() as $f => $d) $vers[dirname($f)] = isset($d['Version']) ? $d['Version'] : '';
    $act = array();
    foreach ($e as $slug => $x) {
        $slug = preg_replace('/[^a-z0-9_\-]/i', '', (string)$slug);
        if ($slug === '') continue;
        // Ya actualizado a otra versión: el escudo de ese fallo deja de hacer falta
        if (isset($vers[$slug]) && !empty($x['version']) && version_compare($vers[$slug], $x['version'], '>')) {
            unset($e[$slug]); update_option('planb_escudo', $e, true); planb_escudo_htaccess($slug, false); continue;
        }
        $act[$slug] = WP_PLUGIN_DIR . '/' . $slug . '/';
    }
    return $act;
}
function planb_escudo_archivo_de($cb)
{
    try {
        if (is_string($cb) && strpos($cb, '::') !== false) $cb = explode('::', $cb);
        if (is_array($cb) && count($cb) === 2) $r = new ReflectionMethod(is_object($cb[0]) ? get_class($cb[0]) : $cb[0], $cb[1]);
        elseif ($cb instanceof Closure || is_string($cb)) $r = new ReflectionFunction($cb);
        elseif (is_object($cb) && method_exists($cb, '__invoke')) $r = new ReflectionMethod($cb, '__invoke');
        else return '';
        return str_replace('\\', '/', (string)$r->getFileName());
    } catch (Exception $e) { return ''; }
}
function planb_escudo_de($archivo, $activos)
{
    if ($archivo === '') return '';
    foreach ($activos as $slug => $dir) if (strpos($archivo, str_replace('\\', '/', $dir)) === 0) return $slug;
    return '';
}
// wp-json: rutas de los plugins con escudo, solo para quien ha entrado
add_filter('rest_request_before_callbacks', function ($res, $handler, $req) {
    if (is_wp_error($res) || is_user_logged_in()) return $res;
    $act = planb_escudo_activos();
    if (!$act || empty($handler['callback'])) return $res;
    if (planb_escudo_de(planb_escudo_archivo_de($handler['callback']), $act) !== '') return new WP_Error('planb_escudo', 'No disponible', array('status' => 403));
    return $res;
}, 1, 3);
// AJAX de visitantes sin sesión (admin-ajax.php hace admin_init antes de la acción)
add_action('admin_init', function () {
    if (!defined('DOING_AJAX') || !DOING_AJAX || is_user_logged_in() || empty($_REQUEST['action'])) return;
    $act = planb_escudo_activos();
    if (!$act) return;
    global $wp_filter;
    $h = 'wp_ajax_nopriv_' . sanitize_key(wp_unslash($_REQUEST['action']));
    if (empty($wp_filter[$h])) return;
    foreach ($wp_filter[$h]->callbacks as $prio) foreach ($prio as $c) {
        if (planb_escudo_de(planb_escudo_archivo_de($c['function']), $act) !== '') { status_header(403); wp_die('No disponible', '', array('response' => 403)); }
    }
}, 0);
/** Pone o quita la prohibición de abrir directamente los .php de un plugin (Apache/LiteSpeed: .htaccess en su carpeta). */
function planb_escudo_htaccess($slug, $poner)
{
    $dir = WP_PLUGIN_DIR . '/' . $slug;
    $f = $dir . '/.htaccess';
    $marca = '# planb-escudo';
    if (!is_dir($dir)) return false;
    if ($poner) {
        if (is_file($f) && strpos((string)@file_get_contents($f), $marca) === false) return false; // ya tenía uno propio: no se toca
        return (bool)@file_put_contents($f, $marca . "\n<FilesMatch \"\\.(php|phtml|phar)$\">\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n</FilesMatch>\n");
    }
    if (is_file($f) && strpos((string)@file_get_contents($f), $marca) !== false) @unlink($f);
    return true;
}
function planb_escudo_ruta(WP_REST_Request $req)
{
    $slug = preg_replace('/[^a-z0-9_\-]/i', '', (string)$req->get_param('slug'));
    if ($slug === '' || $slug === 'planb-conector') return new WP_Error('planb', 'Plugin no válido', array('status' => 400));
    $e = get_option('planb_escudo'); if (!is_array($e)) $e = array();
    $poner = (bool)$req->get_param('poner');
    if ($poner) {
        if (!is_dir(WP_PLUGIN_DIR . '/' . $slug)) return new WP_Error('planb', 'Ese plugin no está en esta web', array('status' => 404));
        $e[$slug] = array('version' => (string)$req->get_param('version'), 'desde' => gmdate('c'));
        $ht = planb_escudo_htaccess($slug, true);
    } else { unset($e[$slug]); $ht = planb_escudo_htaccess($slug, false); }
    update_option('planb_escudo', $e, true);
    return array('escudo' => array_keys(planb_escudo_activos()), 'archivos_bloqueados' => $ht);
}

/*
 * MUDAR UNA WEB (1.7.19 · Jesús, 24/11/2026). Esta web (la de DESTINO, un WordPress recién puesto en el servidor nuevo y ya
 * conectado al panel) recibe la copia completa de otra: baja el zip con su enlace de un solo uso, comprueba la huella, cambia
 * la base de datos y los archivos de wp-content, y cambia la dirección vieja por la nueva (también dentro de datos «serializados»).
 * Se queda con SU conector y SU clave del panel, y con su wp-config.php. Antes, el panel ha hecho un punto de restauración.
 * El estado queda en «planb_importacion» por si el servidor corta la llamada larga: el panel lo pregunta con «importacion».
 */
function planb_importacion(WP_REST_Request $req) { $e = get_option('planb_importacion'); return is_array($e) ? $e : array('estado' => 'nada'); }
function planb_imp_estado($estado, $extra = array()) { update_option('planb_importacion', array_merge(array('estado' => $estado, 'cuando' => gmdate('c')), $extra), false); }
function planb_reemplazar_valor($v, $de, $a)
{
    if (is_string($v)) {
        if ($v !== '' && function_exists('is_serialized') && is_serialized($v)) {
            $u = version_compare(PHP_VERSION, '7.0', '>=') ? @unserialize($v, array('allowed_classes' => false)) : @unserialize($v); // nosemgrep: unserialize-de-fuera — sin clases desde PHP 7
            if ($u !== false || $v === 'b:0;') return serialize(planb_reemplazar_valor($u, $de, $a));
        }
        return str_replace($de, $a, $v);
    }
    if (is_array($v)) { $o = array(); foreach ($v as $k => $x) $o[is_string($k) ? str_replace($de, $a, $k) : $k] = planb_reemplazar_valor($x, $de, $a); return $o; }
    if (is_object($v) && !($v instanceof __PHP_Incomplete_Class)) { foreach (get_object_vars($v) as $k => $x) $v->$k = planb_reemplazar_valor($x, $de, $a); return $v; }
    return $v;
}
/** Cambia textos en todas las tablas de la web (respetando los datos serializados). Devuelve cuántas filas cambia. */
function planb_buscar_reemplazar($de, $a)
{
    global $wpdb;
    $n = 0;
    foreach ($wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($wpdb->prefix) . '%')) as $t) {
        $cols = $wpdb->get_results("SHOW COLUMNS FROM `$t`", ARRAY_A);
        $pk = array(); $txt = array();
        foreach ($cols as $c) {
            if ($c['Key'] === 'PRI') $pk[] = $c['Field'];
            if (preg_match('/char|text|blob|json/i', $c['Type'])) $txt[] = $c['Field'];
        }
        if (!$pk || !$txt) continue;
        $donde = array();
        foreach ($txt as $c) foreach ($de as $d) $donde[] = $wpdb->prepare("`$c` LIKE %s", '%' . $wpdb->esc_like($d) . '%');
        $off = 0;
        do {
            $filas = $wpdb->get_results("SELECT * FROM `$t` WHERE " . implode(' OR ', $donde) . " LIMIT $off, 300", ARRAY_A);
            foreach ($filas as $f) {
                $cambios = array();
                foreach ($txt as $c) { if ($f[$c] === null) continue; $nv = planb_reemplazar_valor($f[$c], $de, $a); if ($nv !== $f[$c]) $cambios[$c] = $nv; }
                if (!$cambios) continue;
                $w = array(); foreach ($pk as $k) $w[$k] = $f[$k];
                if ($wpdb->update($t, $cambios, $w) !== false) $n++;
            }
            $off += 300;
        } while (count($filas) === 300 && $off < 2000000);
    }
    return $n;
}
function planb_importar_copia(WP_REST_Request $req)
{
    @set_time_limit(0); @ignore_user_abort(true);
    global $wpdb;
    $url = (string)$req->get_param('url'); $sha = strtolower((string)$req->get_param('sha256'));
    $viejo = untrailingslashit((string)$req->get_param('desde'));
    if (!preg_match('#^https://#', $url) || !preg_match('/^[a-f0-9]{64}$/', $sha) || !preg_match('#^https?://[^/]+#', $viejo)) return new WP_Error('planb', 'Faltan datos de la copia', array('status' => 400));
    // 1.7.21 (auditoría 1.2): la copia solo se baja de la web de origen de la mudanza (o del propio panel), nunca de otro sitio
    $hu = strtolower((string)parse_url($url, PHP_URL_HOST)); $hv = strtolower((string)parse_url($viejo, PHP_URL_HOST));
    $sinW = function ($h) { return preg_replace('/^www\./', '', $h); };
    if ($sinW($hu) !== $sinW($hv)) return new WP_Error('planb', 'La copia no viene de la web de origen', array('status' => 400)); // 1.7.23: ya no vale desde el panel (no se usaba)
    // 1.7.23 (blindaje): una mudanza solo se pone encima de un WordPress RECIÉN PUESTO (casi sin contenido). Así, ni con el panel
    // en malas manos se puede machacar una web de cliente con la copia de otra.
    $hay = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status NOT IN ('auto-draft','trash','inherit') AND post_type NOT IN ('revision','nav_menu_item','customize_changeset','oembed_cache','user_request','wp_global_styles','wp_navigation','wp_template','wp_template_part','wp_font_family','wp_font_face','attachment')");
    if ($hay > 15) return new WP_Error('planb', 'Esta web ya tiene contenido (' . $hay . ' entradas o páginas): solo se muda encima de un WordPress recién puesto', array('status' => 409));
    if (!class_exists('ZipArchive')) return new WP_Error('sin_zip', 'El servidor no tiene ZipArchive', array('status' => 500));
    planb_imp_estado('bajando');
    $dir = planb_dir_copias();
    $zipf = $dir . '/importar-' . planb_aleatorio(24) . '.zip';
    $r = wp_remote_get($url, array('timeout' => 3600, 'stream' => true, 'filename' => $zipf, 'sslverify' => true));
    if (is_wp_error($r) || (int)wp_remote_retrieve_response_code($r) !== 200 || !is_file($zipf) || hash_file('sha256', $zipf) !== $sha) {
        @unlink($zipf); planb_imp_estado('error', array('error' => 'No se ha podido bajar la copia o no coincide su huella'));
        return new WP_Error('planb', 'No se ha podido bajar la copia o no coincide su huella', array('status' => 500));
    }
    $zip = new ZipArchive();
    if ($zip->open($zipf) !== true) { @unlink($zipf); planb_imp_estado('error', array('error' => 'zip no válido')); return new WP_Error('zip', 'Zip no válido', array('status' => 500)); }
    // 1) Base de datos: lo propio del panel en ESTA web se guarda para volver a ponerlo después
    planb_imp_estado('base de datos');
    $nuevo = untrailingslashit(get_option('home'));
    $nuevoSite = untrailingslashit(get_option('siteurl'));
    $propias = $wpdb->get_results("SELECT option_name, option_value, autoload FROM {$wpdb->options} WHERE option_name LIKE 'planb\\_%'", ARRAY_A);
    $sqlf = $dir . '/importar-' . planb_aleatorio(24) . '.sql';
    $in = $zip->getStream('base-de-datos.sql');
    if (!$in) { $zip->close(); @unlink($zipf); planb_imp_estado('error', array('error' => 'la copia no trae base de datos')); return new WP_Error('planb', 'La copia no trae base de datos', array('status' => 500)); }
    $out = fopen($sqlf, 'w'); stream_copy_to_stream($in, $out); fclose($out); fclose($in);
    // Prefijo de las tablas de la web de origen (por su tabla «options»)
    $viejoPref = null;
    $h = fopen($sqlf, 'r');
    while (($l = fgets($h)) !== false) { if (preg_match('/^DROP TABLE IF EXISTS `([A-Za-z0-9_]+)options`;/', $l, $m) && ($viejoPref === null || strlen($m[1]) < strlen($viejoPref))) $viejoPref = $m[1]; } // la más corta: «wp_options», no «wp_algo_options»
    fclose($h);
    if ($viejoPref === null) { @unlink($sqlf); $zip->close(); @unlink($zipf); planb_imp_estado('error', array('error' => 'no encuentro las tablas de WordPress en la copia')); return new WP_Error('planb', 'Copia sin tablas de WordPress', array('status' => 500)); }
    $pref = $wpdb->prefix;
    foreach ($wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($pref) . '%')) as $t) $wpdb->query("DROP TABLE IF EXISTS `$t`");
    $h = fopen($sqlf, 'r'); $buf = ''; $err = 0;
    $wpdb->query('SET foreign_key_checks=0');
    while (($l = fgets($h)) !== false) {
        if ($buf === '' && $viejoPref !== $pref) $l = preg_replace('/^(DROP TABLE IF EXISTS|CREATE TABLE|INSERT INTO) `' . preg_quote($viejoPref, '/') . '/', '$1 `' . $pref, $l);
        $buf .= $l;
        if (substr(rtrim($l), -1) === ';' && planb_sentencia_completa($buf)) { if ($wpdb->query($buf) === false) $err++; $buf = ''; }
    }
    fclose($h); @unlink($sqlf);
    $wpdb->query('SET foreign_key_checks=1');
    if ($viejoPref !== $pref) {
        $wpdb->query($wpdb->prepare("UPDATE {$wpdb->options} SET option_name=%s WHERE option_name=%s", $pref . 'user_roles', $viejoPref . 'user_roles'));
        $wpdb->query($wpdb->prepare("UPDATE {$wpdb->usermeta} SET meta_key=CONCAT(%s, SUBSTRING(meta_key, %d)) WHERE meta_key LIKE %s", $pref, strlen($viejoPref) + 1, $wpdb->esc_like($viejoPref) . '%'));
    }
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'planb\\_%'");
    foreach ($propias as $o) $wpdb->insert($wpdb->options, $o);
    $wpdb->update($wpdb->options, array('option_value' => $nuevo), array('option_name' => 'home'));
    $wpdb->update($wpdb->options, array('option_value' => $nuevoSite), array('option_name' => 'siteurl'));
    // 2) Dirección vieja → nueva (también https y la forma escapada de JSON)
    planb_imp_estado('direcciones');
    $hv = preg_replace('#^https?://#', '', $viejo); $hn = preg_replace('#^https?://#', '', $nuevo);
    $esqN = parse_url($nuevo, PHP_URL_SCHEME) ?: 'https';
    $cambiadas = 0;
    if ($hv !== $hn) $cambiadas = planb_buscar_reemplazar(array('http://' . $hv, 'https://' . $hv, 'http:\\/\\/' . $hv, 'https:\\/\\/' . $hv, '//' . $hv),
        array($esqN . '://' . $hn, $esqN . '://' . $hn, $esqN . ':\\/\\/' . $hn, $esqN . ':\\/\\/' . $hn, '//' . $hn));
    // 3) Archivos de wp-content (plugins, temas, subidas…), sin tocar este conector
    planb_imp_estado('archivos');
    $raiz = rtrim(ABSPATH, '/');
    $enZip = array();
    for ($i = 0; $i < $zip->numFiles; $i++) { $nm = $zip->getNameIndex($i); if (preg_match('#^web/wp-content/(plugins|themes)/([^/]+)/?#', $nm, $m)) $enZip[$m[1] . '/' . $m[2]] = true; }
    foreach (array('plugins', 'themes') as $c) foreach ((array)glob(WP_CONTENT_DIR . '/' . $c . '/*') as $p) {
        if ($c === 'plugins' && basename($p) === 'planb-conector') continue;
        if (!isset($enZip[$c . '/' . basename($p)])) { is_dir($p) ? planb_borrar_arbol($p) : @unlink($p); }
    }
    $n = 0;
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $nm = $zip->getNameIndex($i);
        if (strpos($nm, 'web/wp-content/') !== 0 || strpos($nm, '..') !== false) continue;
        $rel = substr($nm, 4);
        if (strpos($rel, 'wp-content/plugins/planb-conector/') === 0 || preg_match('#^wp-content/(planb-|cache/|upgrade/)#', $rel)) continue;
        $dest = $raiz . '/' . $rel;
        if (substr($nm, -1) === '/') { wp_mkdir_p($dest); continue; }
        wp_mkdir_p(dirname($dest));
        $s = $zip->getStream($nm); if (!$s) continue;
        $o = @fopen($dest, 'w'); if (!$o) { fclose($s); continue; }
        stream_copy_to_stream($s, $o); fclose($o); fclose($s); $n++;
    }
    $zip->close(); @unlink($zipf);
    wp_cache_flush();
    if (function_exists('opcache_reset')) @opcache_reset();
    delete_option('rewrite_rules');
    planb_vaciar_caches();
    $res = array('archivos' => $n, 'errores_sql' => $err, 'filas_cambiadas' => $cambiadas, 'prefijo_origen' => $viejoPref, 'desde' => $viejo, 'ahora' => $nuevo);
    planb_imp_estado('hecho', $res);
    return $res;
}

/*
 * CORREO DE LA WEB, USUARIOS Y REGISTRO DE CAMBIOS (1.7.20 · Jesús, 24/11/2026)
 * · Correo: se apuntan los envíos que fallan (formularios incluidos) y cuántos salen bien al día. El panel puede mandar uno de prueba.
 * · Usuarios: lista de quien puede entrar con permisos y su último acceso; quitar o devolver el acceso SIN borrar al usuario.
 * · Registro: qué se cambia dentro de WordPress (entradas, plugins, temas, usuarios, ajustes clave) y quién. Se guardan los 2000 últimos.
 */
add_action('wp_mail_failed', function ($e) {
    $f = get_option('planb_correo_fallos'); if (!is_array($f)) $f = array();
    $d = is_object($e) && method_exists($e, 'get_error_data') ? (array)$e->get_error_data() : array();
    array_unshift($f, array('cuando' => gmdate('c'), 'error' => substr(is_object($e) ? $e->get_error_message() : 'error', 0, 200), 'asunto' => substr(isset($d['subject']) ? (string)$d['subject'] : '', 0, 80)));
    update_option('planb_correo_fallos', array_slice($f, 0, 20), false);
});
add_action('wp_mail_succeeded', function () {
    $c = get_option('planb_correo_ok'); if (!is_array($c)) $c = array();
    $hoy = gmdate('Y-m-d'); $c[$hoy] = (isset($c[$hoy]) ? $c[$hoy] : 0) + 1;
    krsort($c); update_option('planb_correo_ok', array_slice($c, 0, 30, true), false);
});
add_action('wpcf7_mail_failed', function () {
    $f = get_option('planb_correo_fallos'); if (!is_array($f)) $f = array();
    array_unshift($f, array('cuando' => gmdate('c'), 'error' => 'Contact Form 7 no ha podido enviar el formulario', 'asunto' => ''));
    update_option('planb_correo_fallos', array_slice($f, 0, 20), false);
});
function planb_correo_web(WP_REST_Request $req)
{
    if (!function_exists('get_plugins')) @include_once ABSPATH . 'wp-admin/includes/plugin.php';
    $smtp = null; $formularios = array();
    $conocidos = array('wp-mail-smtp/' => 'WP Mail SMTP', 'fluent-smtp/' => 'FluentSMTP', 'post-smtp/' => 'Post SMTP', 'easy-wp-smtp/' => 'Easy WP SMTP', 'smtp-mailer/' => 'SMTP Mailer',
        'wp-smtp/' => 'WP SMTP', 'gmail-smtp/' => 'Gmail SMTP', 'mailin/' => 'Brevo', 'sendgrid-email-delivery-simplified/' => 'SendGrid', 'mailgun/' => 'Mailgun', 'wp-ses/' => 'WP Offload SES', 'sureforms/' => null, 'suremails/' => 'SureMails');
    $forms = array('contact-form-7/' => 'Contact Form 7', 'wpforms-lite/' => 'WPForms', 'wpforms/' => 'WPForms', 'gravityforms/' => 'Gravity Forms', 'ninja-forms/' => 'Ninja Forms', 'fluentform/' => 'Fluent Forms',
        'formidable/' => 'Formidable', 'elementor-pro/' => 'Elementor Pro', 'pro-elements/' => 'PRO Elements', 'forminator/' => 'Forminator', 'everest-forms/' => 'Everest Forms', 'sureforms/' => 'SureForms');
    foreach ((array)get_option('active_plugins', array()) as $p) {
        foreach ($conocidos as $k => $n) if ($n && strpos($p, $k) === 0) $smtp = $n;
        foreach ($forms as $k => $n) if (strpos($p, $k) === 0) $formularios[] = $n;
    }
    $f = get_option('planb_correo_fallos'); $c = get_option('planb_correo_ok');
    return array('smtp' => $smtp, 'formularios' => array_values(array_unique($formularios)), 'fallos' => is_array($f) ? $f : array(), 'enviados' => is_array($c) ? $c : array(), 'wp_mail_succeeded' => version_compare($GLOBALS['wp_version'], '5.9', '>='));
}
function planb_probar_correo(WP_REST_Request $req)
{
    $para = sanitize_email((string)$req->get_param('para'));
    if (!is_email($para)) return new WP_Error('planb', 'Correo no válido', array('status' => 400));
    $err = null;
    $h = function ($e) use (&$err) { $err = is_object($e) ? $e->get_error_message() : 'error'; };
    add_action('wp_mail_failed', $h);
    $ok = wp_mail($para, 'Prueba de correo de ' . wp_parse_url(home_url(), PHP_URL_HOST), "Correo de prueba enviado por el panel de mantenimiento desde " . home_url('/') . " el " . gmdate('d/m/Y H:i') . " UTC.\nSi te llega, los formularios de esta web pueden enviar correos.");
    remove_action('wp_mail_failed', $h);
    return array('enviado' => (bool)$ok, 'error' => $err);
}
// Último acceso de cada usuario (para saber qué cuentas no se usan)
add_action('wp_login', function ($login, $u) { if (is_object($u) && !empty($u->ID)) update_user_meta($u->ID, 'planb_ultimo_login', gmdate('c')); }, 10, 2);
function planb_usuarios(WP_REST_Request $req)
{
    $out = array();
    foreach (get_users(array('number' => 400, 'role__not_in' => array('subscriber', 'customer'), 'orderby' => 'registered', 'order' => 'ASC')) as $u) {
        $antes = get_user_meta($u->ID, 'planb_roles_antes', true);
        $out[] = array('id' => $u->ID, 'login' => $u->user_login, 'email' => $u->user_email, 'nombre' => $u->display_name, 'roles' => array_values((array)$u->roles),
            'alta' => $u->user_registered, 'ultimo_login' => get_user_meta($u->ID, 'planb_ultimo_login', true) ?: null, 'bloqueado' => is_array($antes) && $antes ? array_values($antes) : null);
    }
    // También los que el panel bloqueó (ya no tienen rol, así que no salen arriba)
    foreach (get_users(array('meta_key' => 'planb_roles_antes', 'number' => 200)) as $u) {
        $ya = false; foreach ($out as $x) if ($x['id'] === $u->ID) $ya = true;
        if (!$ya) $out[] = array('id' => $u->ID, 'login' => $u->user_login, 'email' => $u->user_email, 'nombre' => $u->display_name, 'roles' => array(), 'alta' => $u->user_registered,
            'ultimo_login' => get_user_meta($u->ID, 'planb_ultimo_login', true) ?: null, 'bloqueado' => array_values((array)get_user_meta($u->ID, 'planb_roles_antes', true)));
    }
    return array('usuarios' => $out, 'total' => (int)count_users()['total_users']);
}
function planb_usuario_acceso(WP_REST_Request $req)
{
    $u = get_user_by('id', (int)$req->get_param('id'));
    if (!$u) return new WP_Error('planb', 'Usuario no encontrado', array('status' => 404));
    if ($req->get_param('quitar')) {
        $roles = array_values((array)$u->roles);
        if (!$roles) return new WP_Error('planb', 'Ese usuario ya no tiene permisos', array('status' => 400));
        if (in_array('administrator', $roles, true) && count(get_users(array('role' => 'administrator', 'fields' => 'ID'))) <= 1) return new WP_Error('planb', 'Es el único administrador: no se le puede quitar el acceso', array('status' => 400));
        update_user_meta($u->ID, 'planb_roles_antes', $roles);
        $u->set_role('');
        if (class_exists('WP_Session_Tokens')) WP_Session_Tokens::get_instance($u->ID)->destroy_all(); // fuera de cualquier sesión abierta
        planb_apuntar('usuario', 'Acceso quitado desde el panel', $u->user_login . ' (' . implode(', ', $roles) . ')');
        return array('ok' => true, 'roles_antes' => $roles);
    }
    $antes = get_user_meta($u->ID, 'planb_roles_antes', true);
    if (!is_array($antes) || !$antes) return new WP_Error('planb', 'No hay permisos guardados para devolver', array('status' => 400));
    $u->set_role(array_shift($antes)); foreach ($antes as $r) $u->add_role($r);
    delete_user_meta($u->ID, 'planb_roles_antes');
    planb_apuntar('usuario', 'Acceso devuelto desde el panel', $u->user_login);
    return array('ok' => true, 'roles' => array_values((array)get_user_by('id', $u->ID)->roles));
}
/* Registro de cambios */
function planb_registro_tabla()
{
    global $wpdb;
    $t = $wpdb->prefix . 'planb_registro';
    if (get_option('planb_registro_tabla') !== '1') {
        $wpdb->query("CREATE TABLE IF NOT EXISTS `$t` (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, fecha DATETIME NOT NULL, usuario VARCHAR(60) NOT NULL DEFAULT '', tipo VARCHAR(20) NOT NULL, accion VARCHAR(120) NOT NULL, objeto VARCHAR(255) NOT NULL DEFAULT '', KEY fecha (fecha)) " . $wpdb->get_charset_collate());
        update_option('planb_registro_tabla', '1', true);
    }
    return $t;
}
function planb_apuntar($tipo, $accion, $objeto = '')
{
    global $wpdb;
    if (defined('WP_INSTALLING') && WP_INSTALLING) return;
    $u = function_exists('wp_get_current_user') ? wp_get_current_user() : null;
    $quien = $u && $u->ID ? $u->user_login : ((defined('REST_REQUEST') && REST_REQUEST && strpos((string)(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : ''), 'planb') !== false) ? 'Panel' : (defined('DOING_CRON') && DOING_CRON ? 'Tarea automática' : 'Sin sesión'));
    $t = planb_registro_tabla();
    $wpdb->insert($t, array('fecha' => current_time('mysql', true), 'usuario' => substr($quien, 0, 60), 'tipo' => $tipo, 'accion' => substr($accion, 0, 120), 'objeto' => substr(wp_strip_all_tags((string)$objeto), 0, 255)));
    if (mt_rand(1, 50) === 1) { $max = (int)$wpdb->get_var("SELECT MAX(id) FROM `$t`"); if ($max > 2000) $wpdb->query($wpdb->prepare("DELETE FROM `$t` WHERE id < %d", $max - 2000)); }
}
add_action('transition_post_status', function ($nuevo, $viejo, $post) {
    if (!is_object($post) || wp_is_post_revision($post) || in_array($post->post_type, array('nav_menu_item', 'customize_changeset', 'oembed_cache', 'wp_global_styles', 'shop_order', 'shop_order_placehold', 'scheduled-action', 'revision', 'attachment', 'wpcf7_contact_form', 'elementor_library', 'jp_mem_plan'), true)) return;
    if ($nuevo === 'auto-draft' || $nuevo === 'inherit') return;
    if ($nuevo === 'publish' && $viejo !== 'publish') $a = 'Publicado';
    elseif ($nuevo === 'trash') $a = 'A la papelera';
    elseif ($viejo === 'publish' && $nuevo !== 'publish') $a = 'Despublicado';
    elseif ($nuevo === 'publish') $a = 'Editado';
    else return;
    planb_apuntar('contenido', $a . ' (' . $post->post_type . ')', $post->post_title);
}, 10, 3);
add_action('before_delete_post', function ($id) { $p = get_post($id); if ($p && !in_array($p->post_type, array('revision', 'nav_menu_item', 'shop_order', 'scheduled-action', 'customize_changeset', 'oembed_cache'), true) && $p->post_status !== 'auto-draft') planb_apuntar('contenido', 'Borrado para siempre (' . $p->post_type . ')', $p->post_title); });
add_action('activated_plugin', function ($p) { planb_apuntar('plugin', 'Plugin activado', $p); });
add_action('deactivated_plugin', function ($p) { planb_apuntar('plugin', 'Plugin desactivado', $p); });
add_action('deleted_plugin', function ($p, $ok) { if ($ok) planb_apuntar('plugin', 'Plugin borrado', $p); }, 10, 2);
add_action('upgrader_process_complete', function ($up, $d) {
    if (empty($d['type']) || empty($d['action'])) return;
    $que = $d['type'] === 'plugin' ? 'Plugin' : ($d['type'] === 'theme' ? 'Tema' : ($d['type'] === 'core' ? 'WordPress' : $d['type']));
    $obj = isset($d['plugins']) ? implode(', ', (array)$d['plugins']) : (isset($d['themes']) ? implode(', ', (array)$d['themes']) : (isset($d['plugin']) ? $d['plugin'] : (isset($d['theme']) ? $d['theme'] : '')));
    planb_apuntar($d['type'], $que . ($d['action'] === 'install' ? ' instalado' : ' actualizado'), $obj);
}, 10, 2);
add_action('switch_theme', function ($n) { planb_apuntar('tema', 'Tema cambiado', $n); });
add_action('user_register', function ($id) { $u = get_userdata($id); if ($u) planb_apuntar('usuario', 'Usuario creado', $u->user_login . ' (' . implode(', ', (array)$u->roles) . ')'); });
add_action('delete_user', function ($id) { $u = get_userdata($id); if ($u) planb_apuntar('usuario', 'Usuario borrado', $u->user_login); });
add_action('set_user_role', function ($id, $rol, $viejos) { $u = get_userdata($id); if ($u && $viejos) planb_apuntar('usuario', 'Rol cambiado', $u->user_login . ': ' . implode(', ', (array)$viejos) . ' → ' . ($rol ?: 'ninguno')); }, 10, 3);
add_action('wp_login', function ($login) { planb_apuntar('acceso', 'Entra en WordPress', $login); }, 20);
add_action('updated_option', function ($op, $viejo, $nuevo) {
    $vigilar = array('siteurl' => 'Dirección de WordPress', 'home' => 'Dirección de la web', 'admin_email' => 'Correo del administrador', 'users_can_register' => 'Cualquiera puede registrarse',
        'default_role' => 'Rol de los registros nuevos', 'blogname' => 'Nombre de la web', 'blog_public' => 'Visible para buscadores', 'permalink_structure' => 'Enlaces permanentes', 'template' => 'Tema', 'WPLANG' => 'Idioma');
    if (!isset($vigilar[$op]) || is_array($viejo) || is_array($nuevo)) return;
    planb_apuntar('ajustes', 'Ajuste cambiado: ' . $vigilar[$op], substr((string)$viejo, 0, 100) . ' → ' . substr((string)$nuevo, 0, 100));
}, 10, 3);
function planb_registro(WP_REST_Request $req)
{
    global $wpdb;
    $t = planb_registro_tabla();
    $desde = max(0, (int)$req->get_param('desde'));
    return array('filas' => $wpdb->get_results($wpdb->prepare("SELECT id, fecha, usuario, tipo, accion, objeto FROM `$t` WHERE id > %d ORDER BY id ASC LIMIT 500", $desde), ARRAY_A));
}

/*
 * BOTS FRENADOS (1.7.12 · Jesús, 23/11/2026). El panel guarda en «planb_bots_frenados» los bots que no deben entrar en esta web
 * (p. ej. ClaudeBot, meta-externalagent, Amazonbot). Se hace de dos formas:
 *  1) robots.txt: se les dice «no entres» (los bots serios hacen caso).
 *  2) Si entran igual, reciben un 403 al momento, antes de que cargue el resto de WordPress (casi no gasta).
 * Quitarlos desde el panel lo deja todo como estaba.
 */
function planb_bots_frenados()
{
    $l = get_option('planb_bots_frenados');
    return is_array($l) ? array_values(array_filter(array_map('strval', $l))) : array();
}
if ($GLOBALS['planb_bots'] = planb_bots_frenados()) {
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string)$_SERVER['HTTP_USER_AGENT'] : '';
    $esRobots = isset($_SERVER['REQUEST_URI']) && strpos((string)$_SERVER['REQUEST_URI'], 'robots.txt') !== false;
    if ($ua !== '' && !$esRobots) foreach ($GLOBALS['planb_bots'] as $b) {
        if (stripos($ua, $b) !== false) { if (!headers_sent()) { status_header(403); header('Content-Type: text/plain; charset=utf-8'); } echo 'Acceso no permitido.'; exit; }
    }
    add_filter('robots_txt', function ($txt) {
        foreach ($GLOBALS['planb_bots'] as $b) $txt .= "\nUser-agent: " . $b . "\nDisallow: /\n";
        return $txt;
    }, 99);
}

/*
 * Certificados al día. Las webs con WordPress o servidor antiguos tienen una lista de certificados caducada
 * y no pueden conectar por HTTPS («cURL error 60»). Para lo que hace el conector (hablar con el panel y descargar
 * actualizaciones cuando el panel lo pide) se usa la lista actual que va dentro del plugin. El resto de la web no cambia.
 */
function planb_en_orden_del_panel()
{
    $ruta = isset($GLOBALS['wp']) && is_object($GLOBALS['wp']) && isset($GLOBALS['wp']->query_vars['rest_route']) ? (string)$GLOBALS['wp']->query_vars['rest_route'] : '';
    if ($ruta === '' && isset($_SERVER['REQUEST_URI'])) $ruta = (string)$_SERVER['REQUEST_URI'];
    return strpos($ruta, 'planb/v1') !== false;
}
add_filter('http_request_args', function ($args, $url) {
    $ca = dirname(__FILE__) . '/cacert.pem';
    if (is_file($ca) && (strpos((string)$url, rtrim(PLANB_PANEL_URL, '/')) === 0 || planb_en_orden_del_panel())) $args['sslcertificates'] = $ca;
    return $args;
}, 10, 2);

/* ───────────── Lista pública de huellas (1.7.22 · blindaje) ─────────────
 * Lo que el panel manda instalar (este conector y los plugins de pago) se comprueba ANTES contra una lista pública
 * de huellas que publica un verificador en GitHub, fuera del servidor del panel. Si alguien tocara el panel, lo que
 * preparase allí no estaría en la lista y esta web no lo instalaría. Sin claves ni contraseñas: todo es público. */
// 1.7.25: la pone el panel al empaquetar (cada panel tiene su propia lista; por defecto, la de Plan B)
if (!defined('PLANB_HUELLAS_URL')) define('PLANB_HUELLAS_URL', '__HUELLAS_URL__');

/** La lista de huellas (10 minutos en memoria). null si no se ha podido leer. */
function planb_huellas($fresca = false)
{
    $c = $fresca ? false : get_transient('planb_huellas');
    if (is_array($c)) return $c;
    $hu = strpos(PLANB_HUELLAS_URL, 'https://') === 0 ? PLANB_HUELLAS_URL : 'https://raw.githubusercontent.com/JesusGil1405/planb-huellas/main/huellas.json';
    $r = wp_remote_get($hu . '?v=' . floor(time() / 60), array('timeout' => 20, 'sslverify' => true, 'redirection' => 0));
    if (is_wp_error($r) || (int)wp_remote_retrieve_response_code($r) !== 200) return null;
    $h = json_decode((string)wp_remote_retrieve_body($r), true);
    if (!is_array($h) || empty($h['formato']) || !isset($h['conector']) || !is_array($h['conector'])) return null;
    set_transient('planb_huellas', $h, 10 * MINUTE_IN_SECONDS);
    return $h;
}

/** Texto de un archivo del conector sin lo que cambia en cada descarga (claves de alta) ni la barra final de la dirección del panel. */
function planb_normalizar_conector($c)
{
    $c = preg_replace("/define\\('PLANB_CLAVE_REGISTRO', '[^']*'\\);/", "define('PLANB_CLAVE_REGISTRO', '');", $c);
    $c = preg_replace("/define\\('PLANB_TOKEN_ALTA', '[^']*'\\);/", "define('PLANB_TOKEN_ALTA', '');", $c);
    return preg_replace_callback("/define\\('PLANB_PANEL_URL', '([^']*)'\\);/", function ($m) { return "define('PLANB_PANEL_URL', '" . rtrim($m[1], '/') . "');"; }, $c);
}

/** Huellas de un conjunto de archivos del conector (nombre => contenido). */
function planb_huellas_de($archivos)
{
    $o = array();
    foreach ($archivos as $n => $c) $o[$n] = hash('sha256', $n === 'planb-conector.php' ? planb_normalizar_conector($c) : $c);
    ksort($o);
    return $o;
}

/** ¿Coinciden las huellas con las de la lista para esa versión? Devuelve '' si sí, o el motivo. */
function planb_comparar_huellas($version, $huellas, $h)
{
    if (!$h) return 'sin_huella: no se ha podido leer la lista de huellas';
    if (!isset($h['conector'][$version]['archivos']) || !is_array($h['conector'][$version]['archivos'])) return 'sin_huella: la versión ' . $version . ' aún no está en la lista';
    $esp = $h['conector'][$version]['archivos']; ksort($esp);
    foreach ($huellas as $n => $s) if (!isset($esp[$n])) return 'archivo que no es del conector: ' . $n;
    foreach ($esp as $n => $s) {
        if (!isset($huellas[$n])) return 'falta ' . $n;
        if (!hash_equals((string)$s, (string)$huellas[$n])) return 'distinto: ' . $n;
    }
    return '';
}

/** Comprueba un zip del conector antes de instalarlo. '' si está en la lista. */
function planb_zip_conector_ok($zipf)
{
    if (!class_exists('ZipArchive')) return 'el servidor no tiene ZipArchive';
    $z = new ZipArchive();
    if ($z->open($zipf) !== true) return 'zip no válido';
    $arch = array();
    for ($i = 0; $i < $z->numFiles; $i++) {
        $n = (string)$z->getNameIndex($i);
        if (substr($n, -1) === '/') continue;
        if (strpos($n, 'planb-conector/') !== 0 || strpos($n, '..') !== false || substr_count($n, '/') !== 1) { $z->close(); return 'archivo que no es del conector: ' . $n; }
        $arch[substr($n, 15)] = (string)$z->getFromIndex($i);
    }
    $z->close();
    $v = isset($arch['planb-conector.php']) && preg_match("/define\\('PLANB_CONECTOR_VERSION', '([0-9.]+)'\\)/", $arch['planb-conector.php'], $m) ? $m[1] : '';
    if ($v === '') return 'el paquete no trae versión';
    $h = planb_huellas();
    $mal = planb_comparar_huellas($v, planb_huellas_de($arch), $h);
    if ($mal !== '' && strpos($mal, 'sin_huella') === 0) $mal = planb_comparar_huellas($v, planb_huellas_de($arch), planb_huellas(true)); // recién publicada: se vuelve a mirar
    return $mal;
}

/**
 * Comprobación diaria de los archivos de ESTE conector contra la lista. El resultado va al panel en «estado».
 * array('estado' => 'ok'|'distinto'|'sin_lista', 'detalle' => …, 'cuando' => …)
 */
function planb_autocomprobar($forzar = false)
{
    $prev = get_option('planb_huella_propia');
    if (!$forzar && is_array($prev) && isset($prev['ts'], $prev['version']) && $prev['version'] === PLANB_CONECTOR_VERSION && $prev['ts'] > time() - DAY_IN_SECONDS) return $prev;
    $dir = dirname(__FILE__); $arch = array();
    foreach ((array)@scandir($dir) as $f) {
        if ($f === '.' || $f === '..' || $f === '' || is_dir($dir . '/' . $f) || preg_match('/^(error_log|php_errorlog)/', $f)) continue; // registros de errores que crean algunos servidores
        $arch[$f] = (string)@file_get_contents($dir . '/' . $f);
    }
    $h = planb_huellas(true);
    $mal = planb_comparar_huellas(PLANB_CONECTOR_VERSION, planb_huellas_de($arch), $h);
    $r = array('estado' => $mal === '' ? 'ok' : (strpos($mal, 'sin_huella') === 0 ? 'sin_lista' : 'distinto'), 'detalle' => $mal, 'version' => PLANB_CONECTOR_VERSION, 'ts' => time(), 'cuando' => gmdate('c'));
    update_option('planb_huella_propia', $r, false);
    if ($r['estado'] === 'distinto') planb_apuntar('seguridad', 'conector distinto del publicado', $mal);
    return $r;
}
add_action('init', function () {
    if (get_transient('planb_huella_mirada') !== false) return;
    set_transient('planb_huella_mirada', 1, DAY_IN_SECONDS);
    planb_autocomprobar(true);
}, 99);

/* ───────────── Limpieza de restos de copias (1.7.21 · auditoría 1.4) ─────────────
 * Si una copia externa del panel se cortó a medias, en la carpeta de la web podían quedar su archivo temporal
 * (planb-copia-*.php) y la copia (planb-copia-*.zip/.sql/.json). Una vez al día se borran los que tengan más de 12 horas.
 * Solo esos nombres exactos: nada más de la web se toca. */
add_action('init', function () {
    if (get_transient('planb_restos_mirados') !== false) return;
    set_transient('planb_restos_mirados', 1, DAY_IN_SECONDS);
    $raiz = rtrim(ABSPATH, '/');
    $borrados = array();
    foreach (array($raiz, dirname($raiz)) as $d) {
        $l = @glob($d . '/planb-copia-*');
        if (!$l) continue;
        foreach ($l as $f) {
            $n = basename($f);
            if (!preg_match('/^planb-copia-([a-f0-9]{12}\.(php|zip|sql|json)|tmp-[a-f0-9]{64})$/', $n)) continue;
            if (@filemtime($f) > time() - 12 * 3600) continue;
            if (is_dir($f)) { foreach ((array)@scandir($f) as $x) if ($x !== '.' && $x !== '..') @unlink($f . '/' . $x); @rmdir($f); }
            else @unlink($f);
            $borrados[] = $n;
        }
    }
    if ($borrados) update_option('planb_restos_borrados', date('Y-m-d H:i') . ': ' . implode(', ', $borrados), false);
});

/* ───────────── Alta automática en el panel ───────────── */
register_activation_hook(__FILE__, 'planb_activar');
// 1.7.26 (auditoría P3.14): al BORRAR el plugin (no al desactivarlo) se quita todo lo suyo: copias, puntos de restauración,
// su clave y sus ajustes. Así no quedan copias de la web ni secretos olvidados en el servidor.
register_uninstall_hook(__FILE__, 'planb_desinstalar');
function planb_desinstalar()
{
    global $wpdb;
    foreach (array(WP_CONTENT_DIR . '/planb-puntos', WP_CONTENT_DIR . '/planb-copias') as $d) if (is_dir($d)) planb_borrar_arbol($d);
    foreach ((array)glob(WP_CONTENT_DIR . '/planb-paquetes-*', GLOB_ONLYDIR) as $d) planb_borrar_arbol($d);
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'planb\\_%' OR option_name LIKE '\\_transient\\_planb\\_%' OR option_name LIKE '\\_transient\\_timeout\\_planb\\_%'");
    $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}planb_registro");
}
function planb_activar()
{
    if (!get_option('planb_secreto')) update_option('planb_secreto', planb_aleatorio(48), false);
    planb_guardar_clave();
    planb_registrar();
}
/** Copia protegida de la clave para el rescate (funciona aunque WordPress no arranque). */
function planb_guardar_clave()
{
    $d = planb_dir_puntos();
    @file_put_contents($d . '/clave.php', '<?php return ' . var_export((string)get_option('planb_secreto'), true) . ';');
}
function planb_aleatorio($n)
{
    if (function_exists('random_bytes')) return bin2hex(random_bytes((int)($n / 2)));
    return bin2hex(openssl_random_pseudo_bytes((int)($n / 2)));
}
function planb_registrar($origen = '')
{
    if (strpos(PLANB_PANEL_URL, '__') === 0) return;
    $t = (string)time();
    $url = home_url('/');
    $sec = get_option('planb_secreto');
    $base = $url . '|' . $sec . '|' . $t;
    $cuerpo = array('url' => $url, 'secreto' => $sec, 't' => $t, 'version' => PLANB_CONECTOR_VERSION, 'rest' => rest_url('planb/v1/'));
    // Con qué se firma (1.7.21): la clave de un solo uso si aún no se ha gastado; si no, la común (conectores antiguos);
    // si no hay ninguna, con el propio secreto (el panel solo lo acepta para una web que ya conoce con ese mismo secreto).
    $tok = (strpos(PLANB_TOKEN_ALTA, '__') !== 0 && !get_option('planb_token_gastado')) ? PLANB_TOKEN_ALTA : '';
    if ($tok !== '') { $cuerpo['firma'] = hash_hmac('sha256', $base, $tok); $cuerpo['token_alta'] = $tok; }
    elseif (strpos(PLANB_CLAVE_REGISTRO, '__') !== 0 && PLANB_CLAVE_REGISTRO !== '') $cuerpo['firma'] = hash_hmac('sha256', $base, PLANB_CLAVE_REGISTRO);
    else $cuerpo['firma'] = hash_hmac('sha256', $base, $sec);
    // Cambio de clave (migración o clave nueva): se firma también con la anterior para que el panel sepa que es legítimo
    $ant = (string)get_option('planb_secreto_anterior');
    if ($ant !== '' && $ant !== $sec) $cuerpo['firma_anterior'] = hash_hmac('sha256', $base, $ant);
    if ($origen !== '') $cuerpo['origen'] = $origen; // 1.7.13: viene de otra dirección (migración)
    $r = wp_remote_post(rtrim(PLANB_PANEL_URL, '/') . '/conector.php', array('timeout' => 20, 'body' => $cuerpo));
    $cod = is_wp_error($r) ? 0 : (int)wp_remote_retrieve_response_code($r);
    $ok = $cod === 200;
    update_option('planb_registro', is_wp_error($r) ? 'error: ' . $r->get_error_message() : 'ok ' . $cod . ' ' . date('Y-m-d H:i'), false);
    if ($ok) {
        update_option('planb_url_registrada', $url, false); delete_option('planb_migracion_pendiente'); delete_option('planb_secreto_anterior');
        if ($tok !== '') update_option('planb_token_gastado', 1, false);
    }
}

/*
 * MIGRACIÓN (1.7.13 · Jesús, 23/11/2026). Las webs en desarrollo (sandbox) se migran al dominio del cliente con el
 * conector ya activado, así que no pasa por «activar». Si la dirección de la web ya no es la que se dio de alta:
 *  · se pone una CLAVE NUEVA (la de la sandbox sigue en la sandbox; así el panel nunca confunde una con otra),
 *  · y se vuelve a dar de alta diciendo de dónde viene, para que el panel le pase el cliente y marque la sandbox como migrada.
 * Se mira como mucho una vez por hora y no cuesta nada (solo compara dos textos).
 */
add_action('init', function () {
    if (strpos(PLANB_PANEL_URL, '__') === 0) return;
    $actual = home_url('/');
    $antes = (string)get_option('planb_url_registrada');
    if ($antes === '') { if (strpos((string)get_option('planb_registro'), 'ok 200') === 0) update_option('planb_url_registrada', $actual, false); return; }
    $h = function ($u) { return preg_replace('/^www\./', '', strtolower((string)parse_url($u, PHP_URL_HOST))); };
    if ($h($antes) === $h($actual)) return;
    if (strpos($h($actual), 'planb-clon') !== false) return; // copias de prueba del panel: nunca se dan de alta
    if (get_transient('planb_migracion_mirada') !== false) return;
    set_transient('planb_migracion_mirada', 1, HOUR_IN_SECONDS);
    if (!get_option('planb_migracion_pendiente')) {
        update_option('planb_migracion_pendiente', $antes, false);
        update_option('planb_secreto_anterior', (string)get_option('planb_secreto'), false); // 1.7.21: para firmar el cambio
        update_option('planb_secreto', planb_aleatorio(48), false);
        planb_guardar_clave();
    }
    planb_registrar((string)get_option('planb_migracion_pendiente'));
});
// Reintenta el alta una vez al día si no quedó registrada.
add_action('admin_init', function () {
    if (!is_file(WP_CONTENT_DIR . '/planb-puntos/clave.php')) planb_guardar_clave();
    $r = (string)get_option('planb_registro');
    if (strpos($r, 'ok 200') !== 0 && get_transient('planb_reintento') === false) {
        set_transient('planb_reintento', 1, DAY_IN_SECONDS);
        if (!get_option('planb_secreto')) update_option('planb_secreto', planb_aleatorio(48), false);
        planb_registrar();
    }
});

/* ───────────── Seguridad: firma HMAC de cada petición ───────────── */
function planb_autorizado(WP_REST_Request $req)
{
    $sec = (string)get_option('planb_secreto');
    $t = (string)$req->get_header('x-planb-tiempo');
    $firma = (string)$req->get_header('x-planb-firma');
    $nonce = (string)$req->get_header('x-planb-nonce');
    if ($sec === '' || $t === '' || $firma === '' || strlen($nonce) < 16 || abs(time() - (int)$t) > 300) return false;
    $esperada = hash_hmac('sha256', $t . '|' . $nonce . '|' . $req->get_method() . '|' . $req->get_route() . '|' . $req->get_body(), $sec);
    if (!hash_equals($esperada, $firma)) return false;
    // 1.7.26 (auditoría P3.14): la firma no cubre la dirección, así que no se admite NADA en ella aparte de la ruta
    // (si alguien añadiese parámetros por el camino, podrían colarse en la orden)
    $q = (array)$req->get_query_params(); unset($q['rest_route']);
    if ($q) return false;
    // Una firma no se puede usar dos veces
    $k = 'planb_n_' . substr($firma, 0, 32);
    if (get_transient($k)) return false;
    set_transient($k, 1, 600);
    return true;
}

add_action('rest_api_init', function () {
    $rutas = array(
        'estado' => array('GET', 'planb_estado'),
        'punto' => array('POST', 'planb_crear_punto'),
        'actualizar' => array('POST', 'planb_actualizar'),
        'restaurar' => array('POST', 'planb_restaurar'),
        'borrar-punto' => array('POST', 'planb_borrar_punto'),
        'clonar' => array('POST', 'planb_clonar'),
        'borrar-clon' => array('POST', 'planb_borrar_clon'),
        'instalar-zip' => array('POST', 'planb_instalar_zip'),
        'licencia' => array('POST', 'planb_licencia'),
        'actualizar-bd' => array('POST', 'planb_actualizar_bd'),
        'php' => array('GET', 'planb_php'),
        'compat' => array('POST', 'planb_compat'),
        'quitar-plugin' => array('POST', 'planb_quitar_plugin'),
        'quitar-tema' => array('POST', 'planb_quitar_tema'),
        'copia-completa' => array('POST', 'planb_copia_completa'),
        'desactivar-plugin' => array('POST', 'planb_desactivar_plugin'),
        'copia-enlace' => array('POST', 'planb_copia_enlace'),
        'borrar-copia' => array('POST', 'planb_borrar_copia'),
        'escanear' => array('POST', 'planb_escanear'),
        'limpiar' => array('POST', 'planb_limpiar'),
        'deshacer-limpieza' => array('POST', 'planb_deshacer_limpieza'),
        'vaciar-cuarentena' => array('POST', 'planb_vaciar_cuarentena'),
        'tanda' => array('POST', 'planb_tanda'),
        'preparar-paquetes' => array('POST', 'planb_preparar_paquetes'),
        'borrar-paquetes' => array('POST', 'planb_borrar_paquetes'),
        'log-picos' => array('GET', 'planb_log_picos'),
        'bots' => array('POST', 'planb_bots_guardar'),
        'vaciar-cache' => array('POST', 'planb_vaciar_caches_ruta'),
        'optimizar-bd' => array('POST', 'planb_optimizar_bd'),
        'tienda' => array('GET', 'planb_tienda'),
        'cobros' => array('GET', 'planb_cobros'),
        'elementor-diag' => array('GET', 'planb_elementor_diag'),
        'elementor-arreglar' => array('POST', 'planb_elementor_arreglar'),
        'empaquetar-plugin' => array('POST', 'planb_empaquetar_plugin'),
        'oew-arranque' => array('POST', 'planb_oew_arranque'),
        'escudo' => array('POST', 'planb_escudo_ruta'),
        'importar-copia' => array('POST', 'planb_importar_copia'),
        'importacion' => array('GET', 'planb_importacion'),
        'correo-web' => array('GET', 'planb_correo_web'),
        'probar-correo' => array('POST', 'planb_probar_correo'),
        'usuarios' => array('GET', 'planb_usuarios'),
        'usuario-acceso' => array('POST', 'planb_usuario_acceso'),
        'registro' => array('GET', 'planb_registro'),
    );
    // 1.7.37: los trabajos que cambian la web van de uno en uno (si hay otro en marcha, responde 409 «ocupada» y el panel espera)
    $pesadas = array('punto', 'actualizar', 'restaurar', 'instalar-zip', 'actualizar-bd', 'quitar-plugin', 'quitar-tema', 'desactivar-plugin', 'limpiar', 'deshacer-limpieza', 'optimizar-bd', 'elementor-arreglar', 'oew-arranque', 'borrar-punto');
    foreach ($rutas as $r => $d) {
        $cb = $d[1];
        if (in_array($r, $pesadas, true) && function_exists('planb_rs_ocupar')) {
            $cb = function (WP_REST_Request $req) use ($r, $d) {
                $dir = planb_dir_puntos();
                if (!planb_rs_ocupar($dir, $r)) {
                    $o = planb_rs_ocupado_info($dir);
                    return new WP_Error('ocupada', 'La web está ocupada con otro trabajo (' . ($o ? $o['que'] . ', desde hace ' . max(0, time() - $o['desde']) . ' s' : '?') . ')', array('status' => 409));
                }
                try { $res = call_user_func($d[1], $req); } catch (Exception $e) { planb_rs_liberar(); throw $e; }
                planb_rs_liberar();
                return $res;
            };
        }
        register_rest_route('planb/v1', '/' . $r, array('methods' => $d[0], 'callback' => $cb, 'permission_callback' => 'planb_autorizado'));
    }
    // Descarga de una copia completa: sin firma, pero solo con un enlace de un solo uso que caduca en 1 hora (lo pide el panel firmado)
    register_rest_route('planb/v1', '/copia-bajar', array('methods' => 'GET', 'callback' => 'planb_copia_bajar', 'permission_callback' => '__return_true'));
});

/**
 * Picos del log (SOLO NÚMEROS): por minuto, cuántas visitas hubo y cuántas dieron error del servidor (5xx).
 * Lee el final del propio log de accesos de la web (ya lo escribe cada visita real). NO devuelve URLs, ni IPs,
 * ni user-agents, ni ningún texto: solo hora, cuenta y errores. Así se cazan microcaídas que el panel no ve
 * entre comprobación y comprobación, sin pedir nada a la web y sin tocar lo que escribió un atacante.
 * Jesús/Andrés, 23/11/2026. Solo lo llama el panel (firmado).
 */
/**
 * Picos del log (por minuto: visitas y errores 5xx). Desde la 1.7.11, en los minutos CON errores dice también quién
 * pedía (Jesús, 23/11/2026, por si son bots): IP recortada (sin el último número) y tipo (bot conocido, bot, navegador,
 * la propia web). Ni páginas, ni la IP completa, ni nada más: lo justo para saber si es un ataque.
 */
function planb_bot_tipo($ua)
{
    $ua = (string)$ua;
    if ($ua === '' || $ua === '-') return 'Sin identificar';
    $conocidos = array('Googlebot', 'bingbot', 'AhrefsBot', 'SemrushBot', 'MJ12bot', 'DotBot', 'PetalBot', 'YandexBot', 'Baiduspider', 'Bytespider', 'GPTBot', 'ChatGPT-User', 'OAI-SearchBot', 'ClaudeBot', 'anthropic-ai', 'PerplexityBot', 'CCBot', 'Amazonbot', 'Applebot', 'facebookexternalhit', 'meta-externalagent', 'DataForSeoBot', 'BLEXBot', 'serpstatbot', 'Barkrowler', 'SeznamBot', 'ImagesiftBot', 'Timpibot', 'MauiBot', 'Screaming Frog', 'python-requests', 'Go-http-client', 'curl', 'Wget', 'zgrab', 'masscan', 'Nuclei', 'WPScan', 'sqlmap', 'Nikto');
    foreach ($conocidos as $b) if (stripos($ua, $b) !== false) return $b;
    if (stripos($ua, 'WordPress/') !== false) return 'La propia web (WordPress)';
    if (stripos($ua, 'PlanB') !== false || stripos($ua, 'Plan B') !== false) return 'Panel Plan B';
    if (preg_match('/bot|crawl|spider|scan|fetch|http-?client|headless|python|java\//i', $ua)) {
        // 1.7.14: en vez de «Otro bot», su nombre (lo que lleva «bot», «crawler»… o la primera palabra si no se hace pasar por navegador)
        if (preg_match('/([A-Za-z][A-Za-z0-9_.\-]{1,40}(?:bot|crawler|spider|scanner|fetcher))/i', $ua, $n)) return substr($n[1], 0, 40);
        if (stripos($ua, 'Mozilla/') !== 0 && preg_match('/^([A-Za-z][A-Za-z0-9_.\-]{1,30})/', $ua, $n)) return $n[1];
        return 'Otro bot';
    }
    return 'Navegador';
}
/** 1.7.14: a qué iba la petición, en pocas palabras (para saber si era un ataque). */
function planb_ruta_tipo($ruta)
{
    $r = strtolower((string)$ruta);
    if (strpos($r, 'wp-login') !== false) return 'wp-login (probar contraseñas)';
    if (strpos($r, 'xmlrpc') !== false) return 'xmlrpc (probar contraseñas)';
    if (preg_match('#/\.(env|git|aws|ssh|htpasswd)|wp-config|\.sql|\.bak|backup|\.zip$|\.tar#', $r)) return 'buscar archivos privados';
    if (preg_match('#phpmyadmin|/pma|shell|cgi-bin|eval-stdin|alfa|wso|\.asp|/vendor/|setup-config|install\.php#', $r)) return 'buscar fallos conocidos';
    if (strpos($r, '/wp-admin') !== false) return 'wp-admin';
    if (strpos($r, '/wp-json') !== false || strpos($r, 'rest_route') !== false) return 'wp-json';
    if (preg_match('#[?&]s=#', $r)) return 'buscador de la web';
    if (strpos($r, '/wp-content/') !== false || strpos($r, '/wp-includes/') !== false) return 'archivos de WordPress';
    return 'páginas';
}
function planb_ip_recortada($ip)
{
    $ip = (string)$ip;
    if (strpos($ip, ':') !== false) { $p = explode(':', $ip); return implode(':', array_slice($p, 0, 3)) . '::'; }
    $p = explode('.', $ip);
    return count($p) === 4 ? $p[0] . '.' . $p[1] . '.' . $p[2] . '.x' : '?';
}
function planb_log_picos(WP_REST_Request $req)
{
    $dir = dirname(rtrim(ABSPATH, '/')) . '/logs';
    $meses = array('Jan' => '01', 'Feb' => '02', 'Mar' => '03', 'Apr' => '04', 'May' => '05', 'Jun' => '06', 'Jul' => '07', 'Aug' => '08', 'Sep' => '09', 'Oct' => '10', 'Nov' => '11', 'Dec' => '12');
    $buckets = array(); // 'Y-m-d H:i' => array(visitas, errores)
    $quien = array();   // 'Y-m-d H:i' => array('ip|tipo' => array(visitas, errores))
    $desde = time() - 3 * 3600 - 300; // últimas ~3 horas (con un margen por la zona horaria)
    foreach (array('access_ssl_log', 'access_log') as $nombre) {
        $f = $dir . '/' . $nombre;
        if (!is_file($f) || !is_readable($f)) continue;
        $tam = (int)@filesize($f);
        $fh = @fopen($f, 'rb');
        if (!$fh) continue;
        if ($tam > 2 * 1048576) @fseek($fh, $tam - 2 * 1048576); // solo el final del archivo
        $datos = (string)@stream_get_contents($fh);
        @fclose($fh);
        foreach (explode("\n", $datos) as $linea) {
            // Formato combinado: IP - - [10/Nov/2026:22:01:03 +0100] "GET ..." 503 123 "ref" "navegador"
            // 1.7.14: también se coge la ruta pedida ($m[7]); el código pasa a $m[8] y el navegador a $m[9]
            if (!preg_match('#^(\S+)\s.*?\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):\d{2}[^\]]*\]\s+"(?:[A-Z]+\s+)?(\S*)[^"]*"\s+(\d{3})(?:\s+\S+\s+"[^"]*"\s+"([^"]*)")?#', $linea, $m)) continue;
            $mes = isset($meses[$m[3]]) ? $meses[$m[3]] : '01';
            $minuto = $m[4] . '-' . $mes . '-' . $m[2] . ' ' . $m[5] . ':' . $m[6];
            $ts = strtotime($minuto);
            if ($ts === false || $ts < $desde) continue;
            if (!isset($buckets[$minuto])) $buckets[$minuto] = array(0, 0);
            $err = (int)$m[8] >= 500 ? 1 : 0;
            $buckets[$minuto][0]++;
            $buckets[$minuto][1] += $err;
            $k = planb_ip_recortada($m[1]) . '|' . planb_bot_tipo(isset($m[9]) ? $m[9] : '');
            if (!isset($quien[$minuto][$k])) $quien[$minuto][$k] = array(0, 0, array());
            $quien[$minuto][$k][0]++;
            $quien[$minuto][$k][1] += $err;
            $que = planb_ruta_tipo($m[7]);
            $quien[$minuto][$k][2][$que] = (isset($quien[$minuto][$k][2][$que]) ? $quien[$minuto][$k][2][$que] : 0) + 1;
        }
    }
    ksort($buckets);
    $out = array();
    foreach ($buckets as $min => $v) {
        $fila = array('m' => $min, 'req' => $v[0], 'err' => $v[1]);
        if ($v[1] > 0 && !empty($quien[$min])) {
            uasort($quien[$min], function ($a, $b) { return $b[0] - $a[0]; });
            $top = array();
            foreach (array_slice($quien[$min], 0, 8, true) as $k => $x) { list($ip, $tipo) = explode('|', $k, 2); arsort($x[2]); $top[] = array('ip' => $ip, 'tipo' => $tipo, 'req' => $x[0], 'err' => $x[1], 'que' => (string)key($x[2])); }
            $fila['quien'] = $top;
        }
        $out[] = $fila;
    }
    return array('picos' => $out, 'hasta' => date('Y-m-d H:i:s'));
}

/**
 * Guarda la lista de bots frenados (ruta «bots», firmada por el panel). Si la web tiene un robots.txt de verdad (archivo),
 * se le añade un bloque marcado «Plan B» que se cambia o se quita entero; si no lo tiene, WordPress lo genera con el filtro de arriba.
 */
function planb_bots_guardar(WP_REST_Request $req)
{
    $p = $req->get_json_params();
    $lista = array();
    foreach ((array)(isset($p['bots']) ? $p['bots'] : array()) as $b) { $b = preg_replace('/[^A-Za-z0-9 ._-]/', '', (string)$b); if ($b !== '') $lista[] = substr($b, 0, 60); }
    $lista = array_values(array_unique($lista));
    if ($lista) update_option('planb_bots_frenados', $lista, true); else delete_option('planb_bots_frenados');
    $f = rtrim(ABSPATH, '/') . '/robots.txt'; $fisico = false;
    if (is_file($f) && is_writable($f)) {
        $fisico = true;
        $t = (string)file_get_contents($f);
        $t = preg_replace('/\n?# >>> Plan B: bots frenados.*?# <<< Plan B\n?/s', "\n", $t);
        if ($lista) { $t = rtrim($t) . "\n\n# >>> Plan B: bots frenados\n"; foreach ($lista as $b) $t .= "User-agent: $b\nDisallow: /\n"; $t .= "# <<< Plan B\n"; }
        file_put_contents($f, rtrim($t) . "\n");
    }
    return array('bots' => $lista, 'robots_fisico' => $fisico);
}

function planb_cargar_admin()
{
    @set_time_limit(900);
    @ignore_user_abort(true);
    if (function_exists('wp_raise_memory_limit')) wp_raise_memory_limit('admin');
    require_once ABSPATH . 'wp-admin/includes/admin.php';
    require_once ABSPATH . 'wp-admin/includes/update.php';
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/misc.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
    if (!function_exists('WP_Filesystem')) require_once ABSPATH . 'wp-admin/includes/file.php';
    WP_Filesystem();
    require_once __DIR__ . '/piel.php';
}

/* ───────────── Estado ───────────── */
/**
 * Si el CSS de Elementor de la web real apunta a un clon de prueba (planb-clon-…), se regenera: pasaba con los clones
 * hechos antes de la 1.7.6, que compartían la carpeta de subidas y dejaban la web sin imágenes de fondo.
 */
function planb_reparar_css_clon()
{
    $dir = wp_upload_dir(null, false);
    $css = rtrim((string)(isset($dir['basedir']) ? $dir['basedir'] : ''), '/') . '/elementor/css';
    if (!is_dir($css)) return false;
    $mal = false;
    foreach ((array)glob($css . '/*.css') as $f) { $t = @file_get_contents($f, false, null, 0, 400000); if ($t !== false && strpos($t, '/planb-clon-') !== false) { $mal = true; break; } }
    if (!$mal) return false;
    if (class_exists('\\Elementor\\Plugin') && isset(\Elementor\Plugin::$instance->files_manager)) \Elementor\Plugin::$instance->files_manager->clear_cache();
    else foreach ((array)glob($css . '/*.css') as $f) @unlink($f);
    return true;
}

function planb_estado(WP_REST_Request $req)
{
    planb_cargar_admin();
    $cssReparado = planb_reparar_css_clon();
    global $wpdb, $wp_version;
    wp_version_check(array(), true);
    wp_update_plugins();
    wp_update_themes();
    $core = get_core_updates();
    $nueva = null;
    if (is_array($core)) foreach ($core as $c) if (isset($c->response) && $c->response === 'upgrade') { $nueva = $c->version; break; }
    $plugins = array();
    $up = get_site_transient('update_plugins');
    $activos = (array)get_option('active_plugins', array());
    foreach (get_plugins() as $file => $p) {
        $plugins[] = array(
            'archivo' => $file, 'nombre' => $p['Name'], 'version' => $p['Version'],
            'nueva' => isset($up->response[$file]) ? $up->response[$file]->new_version : null,
            'activo' => in_array($file, $activos, true),
        );
    }
    $temas = array();
    $ut = get_site_transient('update_themes');
    $activo = get_stylesheet();
    $padre = get_template();
    foreach (wp_get_themes() as $slug => $t) {
        $temas[] = array('slug' => $slug, 'nombre' => $t->get('Name'), 'version' => $t->get('Version'),
            'nueva' => isset($ut->response[$slug]) ? $ut->response[$slug]['new_version'] : null,
            'activo' => $slug === $activo, 'padre' => $slug === $padre && $padre !== $activo);
    }
    $tam = (int)$wpdb->get_var($wpdb->prepare('SELECT SUM(data_length+index_length) FROM information_schema.TABLES WHERE table_schema=%s AND table_name LIKE %s', DB_NAME, $wpdb->esc_like($wpdb->prefix) . '%'));
    $tienda = function_exists('wc_get_page_permalink') ? wc_get_page_permalink('shop') : null;
    return array(
        'conector' => PLANB_CONECTOR_VERSION,
        'restos_borrados' => (string)get_option('planb_restos_borrados'), // 1.7.21: restos de copias borrados (auditoría 1.4)
        'huella' => get_option('planb_huella_propia') ?: null, // 1.7.22: ¿coinciden sus archivos con la lista pública?
        'url' => home_url('/'),
        'escudo' => array_keys(planb_escudo_activos()),
        'admin' => admin_url(),
        'tienda' => $tienda,
        'wp' => $wp_version,
        'wp_nueva' => $nueva,
        'php' => PHP_VERSION,
        'mysql' => $wpdb->db_version(),
        'multisite' => is_multisite(),
        'prefijo' => $wpdb->prefix,
        'bd_mb' => round($tam / 1048576, 1),
        'plugins' => $plugins,
        'temas' => $temas,
        'puntos' => planb_lista_puntos(),
        'rescate' => plugins_url('rescate.php', __FILE__),
        'ruta' => ABSPATH,
        'seguridad' => planb_seguridad(),
    );
}

/* ───────────── Seguridad (solo lectura): administradores, ajustes peligrosos e integridad de WordPress ───────────── */
function planb_seguridad()
{
    $admins = array();
    foreach (get_users(array('role' => 'administrator', 'fields' => array('ID', 'user_login', 'user_email', 'user_registered'))) as $u) {
        $admins[] = array('login' => $u->user_login, 'email' => $u->user_email, 'alta' => $u->user_registered);
    }
    return array(
        'admins' => $admins,
        'debug_visible' => (defined('WP_DEBUG') && WP_DEBUG && (!defined('WP_DEBUG_DISPLAY') || WP_DEBUG_DISPLAY)),
        'editor_archivos' => !(defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT),
        'registro_abierto' => (bool)get_option('users_can_register'),
        'rol_por_defecto' => (string)get_option('default_role'),
        'integridad' => planb_integridad(),
    );
}

/** Compara los archivos de WordPress con las sumas oficiales de wordpress.org (se guarda 12 horas). */
function planb_integridad()
{
    $c = get_transient('planb_integridad');
    if (is_array($c)) return $c;
    global $wp_version;
    $locale = get_locale();
    $sumas = function_exists('get_core_checksums') ? get_core_checksums($wp_version, $locale ? $locale : 'en_US') : false;
    if (!is_array($sumas) || !$sumas) { if (!function_exists('get_core_checksums')) require_once ABSPATH . 'wp-admin/includes/update.php'; $sumas = get_core_checksums($wp_version, 'en_US'); }
    if (!is_array($sumas) || !$sumas) return array('comprobado' => false);
    $cambiados = array(); $faltan = 0;
    foreach ($sumas as $f => $md5) {
        if (strpos($f, 'wp-content/') === 0) continue;
        if ($f === 'wp-config-sample.php' || $f === 'readme.html' || $f === 'license.txt' || strpos($f, 'wp-includes/version.php') === 0) continue;
        $ruta = ABSPATH . $f;
        if (!file_exists($ruta)) { $faltan++; continue; }
        if (md5_file($ruta) !== $md5) $cambiados[] = $f;
    }
    // Archivos PHP sueltos en wp-admin o wp-includes que no son de WordPress (típico de un hackeo)
    $extra = array();
    foreach (array('wp-admin', 'wp-includes') as $dir) {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(ABSPATH . $dir, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $fi) {
            if (count($extra) >= 20) break;
            if (strtolower($fi->getExtension()) !== 'php') continue;
            $rel = ltrim(str_replace(ABSPATH, '', $fi->getPathname()), '/');
            if (!isset($sumas[$rel])) $extra[] = $rel;
        }
    }
    $r = array('comprobado' => true, 'cambiados' => array_slice($cambiados, 0, 20), 'n_cambiados' => count($cambiados), 'faltan' => $faltan, 'extra' => $extra);
    set_transient('planb_integridad', $r, 12 * HOUR_IN_SECONDS);
    return $r;
}

/* ───────────── Puntos de restauración ───────────── */
function planb_dir_puntos()
{
    $d = WP_CONTENT_DIR . '/planb-puntos';
    if (!is_dir($d)) {
        wp_mkdir_p($d);
        @file_put_contents($d . '/.htaccess', "Require all denied\nDeny from all\n");
        @file_put_contents($d . '/index.php', '<?php // silencio');
        @file_put_contents($d . '/web.config', '<configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>');
    }
    return $d;
}
function planb_lista_puntos()
{
    $d = WP_CONTENT_DIR . '/planb-puntos';
    $o = array();
    if (is_dir($d)) foreach (glob($d . '/*', GLOB_ONLYDIR) as $p) {
        $o[] = array('id' => basename($p), 'mb' => round(planb_tam_dir($p) / 1048576, 1));
    }
    return $o;
}
function planb_tam_dir($d)
{
    $t = 0;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) $t += $f->getSize();
    return $t;
}
function planb_excluido($rel)
{
    $fuera = array('.git/', '.svn/', 'node_modules/', 'wp-content/uploads/', 'wp-content/cache/', 'wp-content/planb-puntos/', 'wp-content/upgrade/', 'wp-content/backups', 'wp-content/updraft', 'wp-content/ai1wm-backups', 'wp-content/backup-db', 'wp-content/wflogs', 'wp-content/et-cache', 'wp-snapshots/', 'planb-clon');
    foreach ($fuera as $x) if (strpos($rel, $x) === 0) return true;
    if (strpos($rel, 'wp-content/planb-cuarentena/') === 0) return true;
    // Otra web dentro de esta (p. ej. /tienda/ o /alimentacion/ con su propio WordPress): no es de esta web
    static $otras = null;
    if ($otras === null) {
        $otras = array();
        foreach ((array)glob(rtrim(ABSPATH, '/') . '/*', GLOB_ONLYDIR) as $d) {
            $b = basename($d);
            if (in_array($b, array('wp-admin', 'wp-includes', 'wp-content'), true)) continue;
            if (is_file($d . '/wp-config.php') || is_file($d . '/wp-load.php') || is_file($d . '/config/settings.inc.php') || is_file($d . '/app/config/parameters.php')) $otras[] = $b . '/';
        }
    }
    foreach ($otras as $x) if (strpos($rel, $x) === 0) return true;
    return (bool)preg_match('#\.(zip|tar|gz|wpress|daf|log)$#i', $rel) && strpos($rel, 'wp-content/plugins/') !== 0 && strpos($rel, 'wp-content/themes/') !== 0;
}

/** Copia de seguridad de los archivos de WordPress (sin subidas ni cachés) y de la base de datos. */
function planb_crear_punto(WP_REST_Request $req)
{
    @set_time_limit(900);
    if (!class_exists('ZipArchive')) return new WP_Error('sin_zip', 'El servidor no tiene ZipArchive', array('status' => 500));
    global $wpdb;
    $base = planb_dir_puntos();
    planb_guardar_clave();
    $id = date('Ymd-His') . '-' . planb_aleatorio(32); // 32 caracteres al azar: imposible de adivinar aunque el servidor no respete el .htaccess
    $dir = $base . '/' . $id;
    wp_mkdir_p($dir);
    // 1.7.37: si algo falla, se borra el punto a medias y NO se toca ninguno de los anteriores
    $mal = function ($msg) use ($dir) { planb_borrar_arbol($dir); return new WP_Error('punto', $msg, array('status' => 500)); };
    // Archivos
    $zip = new ZipArchive();
    if ($zip->open($dir . '/archivos.zip', ZipArchive::CREATE) !== true) return $mal('No se pudo crear el zip');
    $raiz = rtrim(ABSPATH, '/');
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($raiz, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    $n = 0;
    foreach ($it as $f) {
        $rel = ltrim(str_replace('\\', '/', substr($f->getPathname(), strlen($raiz))), '/');
        if ($rel === '' || planb_excluido($rel . ($f->isDir() ? '/' : ''))) continue;
        if ($f->isDir()) $zip->addEmptyDir($rel);
        elseif ($f->isReadable() && $f->getSize() < 104857600) { if ($zip->addFile($f->getPathname(), $rel)) $n++; }
    }
    if (!$zip->close()) return $mal('No se pudo terminar el zip (¿falta espacio en el servidor?)');
    clearstatcache();
    $bytesZip = (int)@filesize($dir . '/archivos.zip');
    if ($bytesZip < 1024) return $mal('El zip ha salido vacío');
    $zc = new ZipArchive();
    if ($zc->open($dir . '/archivos.zip') !== true || $zc->numFiles < 10) return $mal('El zip no se puede leer después de crearlo');
    $zc->close();
    // Base de datos (solo las tablas de esta web)
    $sqlf = $dir . '/bd.sql';
    $h = @fopen($sqlf, 'w');
    if (!$h) return $mal('No se pudo crear la copia de la base de datos');
    $esc = fwrite($h, "SET NAMES utf8mb4;\nSET foreign_key_checks=0;\n") ? 0 : 1;
    $tablas = $wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($wpdb->prefix) . '%'));
    foreach ($tablas as $t) {
        $crea = $wpdb->get_row("SHOW CREATE TABLE `$t`", ARRAY_N);
        if (!$crea) continue; // vistas u otras cosas raras
        if (fwrite($h, "DROP TABLE IF EXISTS `$t`;\n" . $crea[1] . ";\n") === false) $esc++;
        $off = 0;
        do {
            $filas = $wpdb->get_results("SELECT * FROM `$t` LIMIT $off, 500", ARRAY_A);
            foreach ((array)$filas as $fila) {
                $vals = array();
                foreach ($fila as $v) $vals[] = $v === null ? 'NULL' : "'" . $wpdb->remove_placeholder_escape(esc_sql($v)) . "'"; // sin el escape de «%» de $wpdb (cambia en cada petición y rompería los datos al restaurar)
                if (fwrite($h, "INSERT INTO `$t` VALUES (" . implode(',', $vals) . ");\n") === false) $esc++;
            }
            $off += 500;
        } while (count((array)$filas) === 500);
        if ($esc > 0) break;
    }
    fwrite($h, "SET foreign_key_checks=1;\n");
    if (!fclose($h) || $esc > 0) return $mal('No se pudo escribir entera la copia de la base de datos (¿falta espacio?)');
    clearstatcache();
    $bytesSql = (int)@filesize($sqlf);
    if ($bytesSql < 200 || !$tablas) return $mal('La copia de la base de datos ha salido vacía');
    file_put_contents($dir . '/info.json', json_encode(array('wp' => $GLOBALS['wp_version'], 'php' => PHP_VERSION, 'tablas' => $tablas, 'archivos' => $n, 'bytes_zip' => $bytesZip, 'bytes_sql' => $bytesSql)));
    // 1.7.37: los puntos viejos se borran DESPUÉS de crear bien el nuevo. Se guardan los 2 últimos además del nuevo;
    // los de menos de 24 h solo se borran si hay más de 4 (para no llenar el disco).
    $puntos = glob($base . '/*', GLOB_ONLYDIR);
    $puntos = array_values(array_filter((array)$puntos, function ($p) use ($dir) { return $p !== $dir && preg_match('/^\d{8}-\d{6}-/', basename($p)); }));
    sort($puntos);
    while (count($puntos) > 2) {
        $viejo = $puntos[0];
        $hora = DateTime::createFromFormat('Ymd-His', substr(basename($viejo), 0, 15));
        $reciente = $hora && $hora->getTimestamp() > time() - 86400;
        if ($reciente && count($puntos) <= 3) break;
        planb_borrar_arbol(array_shift($puntos));
    }
    return array('punto' => $id, 'archivos' => $n, 'tablas' => count($tablas), 'mb' => round(planb_tam_dir($dir) / 1048576, 1), 'bytes_zip' => $bytesZip, 'bytes_sql' => $bytesSql);
}

function planb_restaurar(WP_REST_Request $req)
{
    @set_time_limit(900);
    @ignore_user_abort(true);
    global $wpdb;
    $id = preg_replace('/[^0-9a-z-]/', '', (string)$req->get_param('punto'));
    $dir = WP_CONTENT_DIR . '/planb-puntos/' . $id;
    if (!$id || !is_file($dir . '/archivos.zip') || !is_file($dir . '/bd.sql')) return new WP_Error('no_punto', 'Punto de restauración no encontrado', array('status' => 404));
    // 1.7.37: primero se extrae el zip aparte. Si falla, no se ha tocado nada (ni la base de datos ni los archivos).
    $prep = planb_rs_preparar($dir);
    if (empty($prep['ok'])) return new WP_Error('zip', 'No se restaura: ' . $prep['error'], array('status' => 500));
    // 1) Base de datos
    $h = fopen($dir . '/bd.sql', 'r');
    $buf = ''; $err = 0; $hechas = 0;
    while (($l = fgets($h)) !== false) {
        $buf .= $l;
        if (substr(rtrim($l), -1) === ';' && planb_sentencia_completa($buf)) {
            // Puntos hechos antes de la 1.7.4: el «%» quedó guardado como {hash de 64}; se devuelve a «%»
            $buf = preg_replace('/\{[0-9a-f]{64}\}/', '%', $buf);
            if ($wpdb->query($buf) === false) $err++; else $hechas++;
            $buf = '';
        }
    }
    fclose($h);
    // 2) Archivos: se cambia cada plugin y tema por el del punto (los actuales van a una papelera, no se borran) y el resto encima
    $cambio = planb_rs_cambiar($dir, $prep['tmp'], rtrim(ABSPATH, '/'), rtrim(WP_CONTENT_DIR, '/'));
    wp_cache_flush();
    if (function_exists('opcache_reset')) @opcache_reset();
    return array('restaurado' => !empty($cambio['ok']), 'errores_sql' => $err, 'sentencias' => $hechas, 'problemas' => $cambio['problemas'], 'seguro' => 1);
}
function planb_sentencia_completa($s)
{
    // una sentencia está completa si no queda una comilla simple abierta
    $s = str_replace(array('\\\\', "\\'"), '', $s);
    return substr_count($s, "'") % 2 === 0;
}
function planb_borrar_punto(WP_REST_Request $req)
{
    $id = preg_replace('/[^0-9a-z-]/', '', (string)$req->get_param('punto'));
    if ($id) planb_borrar_arbol(WP_CONTENT_DIR . '/planb-puntos/' . $id);
    return array('ok' => true);
}
function planb_borrar_arbol($d)
{
    if (is_link($d) || is_file($d)) return @unlink($d);
    if (!is_dir($d)) return false;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
    return @rmdir($d);
}

/* ───────────── Actualizaciones ───────────── */
/** Mientras el conector actualiza: sin traducciones automáticas y sin textos sueltos que estropeen la respuesta al panel. */
function planb_silencio_empezar()
{
    add_filter('auto_update_translation', '__return_false');
    add_filter('async_update_translation', '__return_false');
    ob_start();
}
function planb_silencio_terminar() { while (ob_get_level() > 0) @ob_end_clean(); }

function planb_actualizar(WP_REST_Request $req)
{
    planb_silencio_empezar();
    planb_cargar_admin();
    wp_update_plugins(); wp_update_themes(); wp_version_check(array(), true);
    $res = array('plugins' => array(), 'temas' => array(), 'core' => null, 'errores' => array());
    $plugins = (array)$req->get_param('plugins');
    $temas = (array)$req->get_param('temas');
    // De uno en uno: si uno falla, los demás siguen, y se sabe el motivo exacto de cada fallo
    $motivo = function ($r, $piel) {
        if (is_wp_error($r)) return $r->get_error_message();
        $m = array_values(array_filter(array_map('wp_strip_all_tags', $piel->msgs)));
        return $m ? implode(' · ', array_slice($m, -3)) : 'sin detalle';
    };
    if ($plugins) {
        $activos = (array)get_option('active_plugins', array());
        foreach ($plugins as $p) {
            $piel = new Planb_Piel_Silenciosa();
            $up = new Plugin_Upgrader($piel);
            // Cada actualización borra la lista de «hay versión nueva» de WordPress: sin esto, del segundo plugin en
            // adelante WordPress dice «up_to_date» y no los actualiza (1.7.5). Se pide de nuevo si falta.
            $lista = get_site_transient('update_plugins');
            if (empty($lista->response[$p])) { delete_site_transient('update_plugins'); wp_update_plugins(); $lista = get_site_transient('update_plugins'); }
            $zip = empty($lista->response[$p]) ? planb_paquete_local($p) : '';
            if ($zip !== '') {
                // Plugin de pago en la copia de prueba: la licencia no vale aquí (otra dirección), así que se instala
                // la versión nueva que la web real descargó con su licencia (1.7.7)
                $r = $up->install($zip, array('overwrite_package' => true, 'clear_update_cache' => false));
                if ($r && !is_wp_error($r)) $res['desde_paquete'][] = $p;
            } else {
                $r = $up->upgrade($p, array('clear_update_cache' => false));
            }
            $res['plugins'][$p] = $r && !is_wp_error($r);
            if (!$res['plugins'][$p]) $res['errores']['p:' . $p] = $motivo($r, $piel);
            if (in_array($p, $activos, true) && !is_plugin_active($p)) activate_plugin($p, '', false, true); // se deja activo como estaba
        }
    }
    foreach ($temas as $t) {
        $piel = new Planb_Piel_Silenciosa();
        $up = new Theme_Upgrader($piel);
        $lista = get_site_transient('update_themes');
        if (empty($lista->response[$t])) { delete_site_transient('update_themes'); wp_update_themes(); }
        $r = $up->upgrade($t, array('clear_update_cache' => false));
        $res['temas'][$t] = $r && !is_wp_error($r);
        if (!$res['temas'][$t]) $res['errores']['t:' . $t] = $motivo($r, $piel);
    }
    // Por si una actualización se cortó: la web nunca se queda en «modo mantenimiento»
    if (is_file(ABSPATH . '.maintenance')) @unlink(ABSPATH . '.maintenance');
    wp_clean_plugins_cache(true); wp_clean_themes_cache(true); // al final, la lista se limpia como siempre
    $core = (string)$req->get_param('core');
    if ($core !== '') {
        $act = null;
        foreach ((array)get_core_updates() as $c) if (isset($c->version) && $c->version === $core) $act = $c;
        if ($act) {
            $up = new Core_Upgrader(new Planb_Piel_Silenciosa());
            $r = $up->upgrade($act);
            $res['core'] = is_wp_error($r) ? $r->get_error_message() : (string)$r;
            // La base de datos se pone al día en otra llamada (actualizar-bd): en esta, el código viejo sigue cargado en memoria
            $res['necesita_bd'] = !is_wp_error($r);
        } else $res['core'] = 'versión no disponible';
    }
    wp_cache_flush();
    // 1.7.16: después de actualizar se vacían las cachés de página (si no, los visitantes pueden ver la versión vieja)
    $res['caches'] = planb_vaciar_caches();
    planb_silencio_terminar();
    return $res;
}

/**
 * Vacía las cachés de los plugins más usados (WP Rocket, LiteSpeed, W3 Total Cache, WP Super Cache, WP Fastest Cache,
 * Autoptimize, SiteGround, Breeze, Hummingbird, Elementor, Divi) y la de objetos. Devuelve cuáles ha vaciado.
 */
function planb_vaciar_caches()
{
    $hecho = array();
    try {
        if (function_exists('rocket_clean_domain')) { rocket_clean_domain(); $hecho[] = 'WP Rocket'; }
        if (has_action('litespeed_purge_all') || class_exists('LiteSpeed\\Purge')) { do_action('litespeed_purge_all'); $hecho[] = 'LiteSpeed'; }
        if (function_exists('w3tc_flush_all')) { w3tc_flush_all(); $hecho[] = 'W3 Total Cache'; }
        if (function_exists('wp_cache_clear_cache')) { wp_cache_clear_cache(); $hecho[] = 'WP Super Cache'; }
        if (isset($GLOBALS['wp_fastest_cache']) && method_exists($GLOBALS['wp_fastest_cache'], 'deleteCache')) { $GLOBALS['wp_fastest_cache']->deleteCache(true); $hecho[] = 'WP Fastest Cache'; }
        if (class_exists('autoptimizeCache') && method_exists('autoptimizeCache', 'clearall')) { autoptimizeCache::clearall(); $hecho[] = 'Autoptimize'; }
        if (function_exists('sg_cachepress_purge_cache')) { sg_cachepress_purge_cache(); $hecho[] = 'SiteGround'; }
        if (class_exists('Breeze_PurgeCache') && method_exists('Breeze_PurgeCache', 'breeze_cache_flush')) { Breeze_PurgeCache::breeze_cache_flush(); $hecho[] = 'Breeze'; }
        if (has_action('wphb_clear_page_cache')) { do_action('wphb_clear_page_cache'); $hecho[] = 'Hummingbird'; }
        if (class_exists('\\Elementor\\Plugin') && isset(\Elementor\Plugin::$instance->files_manager)) { \Elementor\Plugin::$instance->files_manager->clear_cache(); $hecho[] = 'Elementor'; }
        if (function_exists('et_core_page_resource_auto_clear')) { et_core_page_resource_auto_clear(); $hecho[] = 'Divi'; }
    } catch (Throwable $e) { $hecho[] = 'error: ' . $e->getMessage(); }
    wp_cache_flush();
    if (function_exists('opcache_reset')) @opcache_reset();
    return $hecho;
}
function planb_vaciar_caches_ruta(WP_REST_Request $req) { return array('caches' => planb_vaciar_caches()); }

/**
 * 1.7.34 · Arranque de Ocean Elementor Widgets (León, 25/11/2026): en alguna web su parte principal no arranca y sus bloques
 * no salen. Un mu-plugin, justo antes de que arranque Elementor, lo arranca SOLO si no ha arrancado y nadie lo va a arrancar.
 */
function planb_oew_arranque(WP_REST_Request $req)
{
    $f = WPMU_PLUGIN_DIR . '/planb-oew-arranque.php';
    if (!$req->get_param('poner')) { $q = is_file($f) ? @unlink($f) : true; return array('quitado' => (bool)$q); }
    if (!is_dir(WPMU_PLUGIN_DIR)) wp_mkdir_p(WPMU_PLUGIN_DIR);
    $c = "<?php\n/* Plan B: arranca Ocean Elementor Widgets si no ha arrancado (lo pone y lo quita el panel). */\n"
       . "add_action('init', function () {\n"
       . "    if (class_exists('owpElementor\\\\owpElementorPlugin', false) || !class_exists('Ocean_Elementor_Widgets', false) || did_action('elementor/init')) return;\n"
       . "    \$t = wp_get_theme(); if ('OceanWP' !== \$t->get('Name') && 'oceanwp' !== \$t->get_template()) return;\n"
       . "    global \$wp_filter;\n"
       . "    foreach (\$wp_filter as \$h) { if (!is_object(\$h) || empty(\$h->callbacks)) continue; foreach (\$h->callbacks as \$cbs) foreach (\$cbs as \$cb) if (is_array(\$cb['function']) && isset(\$cb['function'][1]) && \$cb['function'][1] === 'setup' && \$cb['function'][0] instanceof Ocean_Elementor_Widgets) return; }\n"
       . "    \$o = Ocean_Elementor_Widgets::instance(); if (method_exists(\$o, 'setup')) \$o->setup();\n"
       . "    \$u = (int)get_option('planb_oew_arranque_usado'); if (time() - \$u > 3600) update_option('planb_oew_arranque_usado', time(), false);\n"
       . "}, -1);\n";
    $ok = @file_put_contents($f, $c) !== false;
    return array('puesto' => $ok);
}

/**
 * 1.7.30 · Empaqueta un plugin instalado tal cual (para copiarlo a otra web del panel cuando en esa está dañado; Jesús,
 * 25/11/2026, León/Oviedo). Devuelve el zip en base64 al panel, que es quien lo instala en la otra web con su huella.
 */
function planb_empaquetar_plugin(WP_REST_Request $req)
{
    $slug = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$req->get_param('slug'));
    $dir = WP_PLUGIN_DIR . '/' . $slug;
    if ($slug === '' || $slug === 'planb-conector' || !is_dir($dir)) return new WP_Error('no', 'Esta web no tiene ese plugin', array('status' => 404));
    if (!class_exists('ZipArchive')) return new WP_Error('zip', 'El servidor no tiene ZipArchive', array('status' => 500));
    @set_time_limit(300);
    planb_cargar_admin();
    $tmp = wp_tempnam('planb-pl');
    $z = new ZipArchive();
    if ($z->open($tmp, ZipArchive::OVERWRITE | ZipArchive::CREATE) !== true) return new WP_Error('zip', 'No se pudo crear el zip', array('status' => 500));
    $n = 0; $tam = 0;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    foreach ($it as $f) {
        $rel = $slug . '/' . str_replace('\\', '/', substr($f->getPathname(), strlen($dir) + 1));
        if ($f->isDir()) { $z->addEmptyDir($rel); continue; }
        if ($f->isLink()) continue;
        $tam += $f->getSize();
        if ($tam > 60 * 1048576) { $z->close(); @unlink($tmp); return new WP_Error('grande', 'El plugin ocupa más de 60 MB', array('status' => 413)); }
        $z->addFile($f->getPathname(), $rel); $n++;
    }
    $z->close();
    $datos = (string)file_get_contents($tmp); @unlink($tmp);
    $version = '';
    foreach (get_plugins() as $pf => $pd) if (strpos($pf, $slug . '/') === 0) $version = $pd['Version'];
    return array('slug' => $slug, 'version' => $version, 'archivos' => $n, 'sha256' => hash('sha256', $datos), 'zip' => base64_encode($datos));
}

/**
 * 1.7.29 · Diagnóstico de Elementor (Jesús, 25/11/2026: en León los bloques de productos de la portada no salían y no
 * había acceso al escritorio). Solo lee: qué bloques usa la portada, cuáles conoce Elementor y cuáles no, opciones de
 * los plugins de Ocean, caché de elementos y los últimos errores del registro que hablen de Elementor u Ocean.
 */
function planb_elementor_tipos($els, &$tipos)
{
    if (!is_array($els)) return;
    foreach ($els as $e) {
        if (!is_array($e)) continue;
        if (isset($e['elType']) && $e['elType'] === 'widget' && !empty($e['widgetType'])) { $t = (string)$e['widgetType']; $tipos[$t] = isset($tipos[$t]) ? $tipos[$t] + 1 : 1; }
        if (!empty($e['elements'])) planb_elementor_tipos($e['elements'], $tipos);
    }
}
function planb_elementor_diag(WP_REST_Request $req)
{
    global $wpdb;
    $r = array('elementor' => defined('ELEMENTOR_VERSION') ? ELEMENTOR_VERSION : null, 'pro' => defined('ELEMENTOR_PRO_VERSION') ? ELEMENTOR_PRO_VERSION : null);
    $id = (int)$req->get_param('pagina'); if (!$id) $id = (int)get_option('page_on_front');
    $r['pagina'] = $id;
    $datos = json_decode((string)get_post_meta($id, '_elementor_data', true), true);
    $tipos = array(); planb_elementor_tipos($datos, $tipos); $r['bloques_pagina'] = $tipos;
    $r['registrados_oew'] = array(); $r['faltan'] = array();
    try {
        if (class_exists('\\Elementor\\Plugin') && isset(\Elementor\Plugin::$instance->widgets_manager)) {
            $reg = \Elementor\Plugin::$instance->widgets_manager->get_widget_types();
            $r['registrados'] = count($reg);
            foreach (array_keys($reg) as $k) if (strpos($k, 'oew') === 0) $r['registrados_oew'][] = $k;
            foreach ($tipos as $t => $n) if (!isset($reg[$t])) $r['faltan'][] = $t;
        }
    } catch (Exception $e) { $r['error_widgets'] = $e->getMessage(); }
    $r['clases'] = array('Ocean_Elementor_Widgets' => class_exists('Ocean_Elementor_Widgets'), 'Ocean_Extra' => class_exists('Ocean_Extra'), 'OceanWP_Theme_Class' => class_exists('OceanWP_Theme_Class'), 'WooCommerce' => class_exists('WooCommerce'));
    $r['plugins_activos'] = array_values((array)get_option('active_plugins'));
    $r['tema'] = get_option('stylesheet') . ' / ' . get_option('template');
    $ops = array();
    foreach ((array)$wpdb->get_results("SELECT option_name, LEFT(option_value, 300) v FROM {$wpdb->options} WHERE option_name LIKE 'oew%' OR option_name LIKE 'oe\\_%' OR option_name LIKE 'ocean%' OR option_name LIKE 'elementor\\_experiment%' OR option_name LIKE 'elementor\\_element\\_cache%' OR option_name LIKE 'elementor\\_disabled%' OR option_name LIKE 'elementor\\_safe%' LIMIT 80") as $o) $ops[$o->option_name] = $o->v;
    $r['opciones'] = $ops;
    $r['cache_elementos'] = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->postmeta} WHERE meta_key='_elementor_element_cache'");
    $r['cache_portada'] = (bool)get_post_meta($id, '_elementor_element_cache', true);
    $log = array();
    foreach (array(WP_CONTENT_DIR . '/debug.log', ini_get('error_log'), ABSPATH . 'error_log') as $f) {
        if (!$f || !is_file($f) || !is_readable($f)) continue;
        $fh = @fopen($f, 'rb'); if (!$fh) continue;
        $tam = filesize($f); fseek($fh, max(0, $tam - 300000)); $txt = (string)fread($fh, 300000); fclose($fh);
        foreach (array_reverse(explode("\n", $txt)) as $l) { if (stripos($l, 'ocean') !== false || stripos($l, 'elementor') !== false) { $log[] = substr($l, 0, 400); if (count($log) >= 15) break; } }
    }
    $r['errores'] = $log;
    // 1.7.31: quién engancha a Elementor, qué clases de Ocean hay cargadas y qué condiciones tiene el código de Ocean Elementor Widgets
    global $wp_filter;
    $gan = array();
    foreach (array('elementor/widgets/register', 'elementor/widgets/widgets_registered', 'elementor/init', 'elementor/loaded', 'plugins_loaded', 'after_setup_theme', 'init') as $h) {
        if (empty($wp_filter[$h])) continue;
        foreach ($wp_filter[$h]->callbacks as $prio => $cbs) foreach ($cbs as $cb) {
            $f = $cb['function']; $n = '';
            if (is_string($f)) $n = $f; elseif (is_array($f)) $n = (is_object($f[0]) ? get_class($f[0]) : (string)$f[0]) . '::' . (string)$f[1]; elseif (is_object($f)) $n = get_class($f);
            if (stripos($n, 'oew') !== false || stripos($n, 'ocean') !== false) $gan[] = $h . ' ' . $prio . ' ' . $n;
        }
    }
    $r['enganches'] = $gan;
    $cl = array(); foreach (get_declared_classes() as $c) if (stripos($c, 'oew') !== false || stripos($c, 'ocean') !== false) $cl[] = $c;
    $r['clases_ocean'] = array_slice($cl, 0, 80);
    $cod = array();
    $base = WP_PLUGIN_DIR . '/ocean-elementor-widgets';
    foreach (array('ocean-elementor-widgets.php', 'includes/plugin.php') as $f) {
        if (!is_file($base . '/' . $f)) { $cod[] = $f . ': NO EXISTE'; continue; }
        foreach (file($base . '/' . $f) as $i => $l) {
            if (preg_match('/(return\b|get_option|license|licen|wp_get_theme|->name|template|version_compare|is_admin|did_action|class_exists|defined\(|add_action\(|require)/i', $l)) $cod[] = $f . ':' . ($i + 1) . ' ' . substr(trim($l), 0, 170);
            if (count($cod) >= 120) break 2;
        }
    }
    $r['oew_codigo'] = $cod;
    // 1.7.32: todo lo que engancha a Elementor (sin filtrar) y el trozo de código donde Ocean Elementor Widgets decide
    $todo = array();
    foreach (array('elementor/widgets/register', 'elementor/init', 'elementor/loaded') as $h) {
        if (empty($wp_filter[$h])) { $todo[] = $h . ': (nada)'; continue; }
        foreach ($wp_filter[$h]->callbacks as $prio => $cbs) foreach ($cbs as $cb) {
            $f = $cb['function']; $n = '?';
            if (is_string($f)) $n = $f; elseif (is_array($f)) $n = (is_object($f[0]) ? get_class($f[0]) : (string)$f[0]) . '::' . (string)$f[1]; elseif ($f instanceof Closure) $n = 'closure'; elseif (is_object($f)) $n = get_class($f);
            $todo[] = $h . ' ' . $prio . ' ' . $n;
        }
    }
    $r['enganches_elementor'] = array_slice($todo, 0, 120);
    $r['acciones_hechas'] = array('elementor/loaded' => did_action('elementor/loaded'), 'elementor/init' => did_action('elementor/init'), 'elementor/widgets/register' => did_action('elementor/widgets/register'), 'plugins_loaded' => did_action('plugins_loaded'));
    $trozo = array();
    if (is_file($base . '/includes/plugin.php')) { $ls = file($base . '/includes/plugin.php'); for ($i = 150; $i < min(count($ls), 300); $i++) { $t = rtrim($ls[$i]); if (trim($t) !== '' && strpos(ltrim($t), '*') !== 0 && strpos(ltrim($t), '/') !== 0) $trozo[] = ($i + 1) . ' ' . substr($t, 0, 160); } }
    $r['oew_plugin_150_300'] = $trozo;
    $mm = array();
    foreach ((array)glob($base . '/includes/*manager*.php') as $f) { foreach (file($f) as $i => $l) { $t = rtrim($l); if (trim($t) !== '' && strpos(ltrim($t), '*') !== 0 && strpos(ltrim($t), '/') !== 0) $mm[] = basename($f) . ':' . ($i + 1) . ' ' . substr($t, 0, 160); if (count($mm) >= 150) break 2; } }
    $r['oew_manager'] = $mm;
    $r['orden_plugins'] = array_values((array)get_option('active_plugins'));
    // 1.7.33: por qué no arranca: la marca de pruebas, el principio y el final de includes/plugin.php y dónde aparece la marca
    $r['owp_tests_definida'] = defined('OWP_ELEMENTOR_TESTS');
    $pi = array();
    if (is_file($base . '/includes/plugin.php')) { $ls = file($base . '/includes/plugin.php'); $n = count($ls); foreach ($ls as $i => $l) { if ($i < 50 || $i >= $n - 25) { $t = rtrim($l); if (trim($t) !== '') $pi[] = ($i + 1) . ' ' . substr($t, 0, 160); } } }
    $r['oew_plugin_extremos'] = $pi;
    $donde = array();
    $mira = array(ABSPATH . 'wp-config.php', dirname(ABSPATH) . '/wp-config.php');
    foreach ((array)glob(WPMU_PLUGIN_DIR . '/*.php') as $f) $mira[] = $f;
    foreach ((array)glob(get_template_directory() . '/*.php') as $f) $mira[] = $f;
    if (get_stylesheet_directory() !== get_template_directory()) foreach ((array)glob(get_stylesheet_directory() . '/*.php') as $f) $mira[] = $f;
    foreach ((array)glob(WP_PLUGIN_DIR . '/*/*.php') as $f) $mira[] = $f;
    foreach ($mira as $f) { if (!is_file($f) || filesize($f) > 3000000) continue; $c = (string)@file_get_contents($f); if (strpos($c, 'OWP_ELEMENTOR_TESTS') !== false) $donde[] = str_replace(ABSPATH, '', $f); }
    $r['owp_tests_donde'] = $donde;
    $mu = array(); foreach ((array)glob(WPMU_PLUGIN_DIR . '/*') as $f) $mu[] = basename($f) . ' ' . @filesize($f);
    $r['mu_plugins'] = $mu;
    // 1.7.35: el arranque de Ocean Elementor Widgets tal cual (líneas 100-250 del archivo principal) y si el parche del panel ha hecho falta
    $prin = array();
    if (is_file($base . '/ocean-elementor-widgets.php')) { $ls = file($base . '/ocean-elementor-widgets.php'); for ($i = 99; $i < min(count($ls), 250); $i++) { $t = rtrim($ls[$i]); if (trim($t) !== '' && strpos(ltrim($t), '*') !== 0 && strpos(ltrim($t), '/') !== 0) $prin[] = ($i + 1) . ' ' . substr($t, 0, 170); } }
    $r['oew_principal'] = $prin;
    $r['arranque_usado'] = get_option('planb_oew_arranque_usado');
    $r['tema_opciones'] = array('template' => get_option('template'), 'stylesheet' => get_option('stylesheet'), 'current_theme' => get_option('current_theme'));
    $ops2 = array();
    foreach ((array)$wpdb->get_results("SELECT option_name, LEFT(option_value, 400) v FROM {$wpdb->options} WHERE option_name LIKE '%oew%' OR option_name LIKE '%elementor_widget%' OR option_name LIKE 'oe\\_%' OR option_name LIKE 'oceanwp%' LIMIT 60") as $o) $ops2[$o->option_name] = $o->v;
    $r['opciones_oew'] = $ops2;
    $th = wp_get_theme();
    $r['tema_nombre'] = $th->get('Name') . ' / plantilla ' . $th->get_template() . ' / ' . $th->get('Version');
    return $r;
}
/** 1.7.29 · Borra la caché de elementos de Elementor (lo ya pintado de cada bloque) y sus archivos CSS. */
function planb_elementor_arreglar(WP_REST_Request $req)
{
    global $wpdb;
    $n = (int)$wpdb->query("DELETE FROM {$wpdb->postmeta} WHERE meta_key IN ('_elementor_element_cache','_elementor_css')");
    $c = planb_vaciar_caches();
    return array('borrados' => $n, 'caches' => $c);
}

/**
 * 1.7.16 · Optimizar la base de datos. Con «mirar» solo cuenta; con «hacer» borra lo que sobra y optimiza las tablas.
 * Solo lo que no hace falta: revisiones de más de 90 días (siempre se quedan las 3 últimas de cada página), borradores
 * automáticos de más de 7 días, comentarios de spam y de la papelera, cachés caducadas (transients) y datos huérfanos.
 * La papelera de entradas NO se toca (se puede querer recuperar algo). El panel hace una copia de seguridad antes.
 */
function planb_optimizar_bd(WP_REST_Request $req)
{
    global $wpdb;
    @set_time_limit(600);
    $hacer = (string)$req->get_param('modo') === 'hacer';
    $p = $wpdb->posts; $pm = $wpdb->postmeta; $c = $wpdb->comments; $cm = $wpdb->commentmeta;
    // Revisiones viejas, menos las 3 últimas de cada página
    $revViejas = $wpdb->get_col("SELECT r.ID FROM $p r WHERE r.post_type='revision' AND r.post_modified < NOW() - INTERVAL 90 DAY
        AND (SELECT COUNT(*) FROM $p r2 WHERE r2.post_type='revision' AND r2.post_parent=r.post_parent AND r2.post_modified > r.post_modified) >= 3 LIMIT 20000");
    $cuentas = array(
        'revisiones' => count($revViejas),
        'borradores_automaticos' => (int)$wpdb->get_var("SELECT COUNT(*) FROM $p WHERE post_status='auto-draft' AND post_date < NOW() - INTERVAL 7 DAY"),
        'comentarios_spam' => (int)$wpdb->get_var("SELECT COUNT(*) FROM $c WHERE comment_approved='spam'"),
        'comentarios_papelera' => (int)$wpdb->get_var("SELECT COUNT(*) FROM $c WHERE comment_approved='trash'"),
        'caches_caducadas' => (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s AND option_value < %d", $wpdb->esc_like('_transient_timeout_') . '%', time())),
        'datos_huerfanos' => (int)$wpdb->get_var("SELECT COUNT(*) FROM $pm m LEFT JOIN $p x ON x.ID=m.post_id WHERE x.ID IS NULL") + (int)$wpdb->get_var("SELECT COUNT(*) FROM $cm m LEFT JOIN $c x ON x.comment_ID=m.comment_id WHERE x.comment_ID IS NULL"),
    );
    $tam = function () use ($wpdb) { return (int)$wpdb->get_var($wpdb->prepare('SELECT SUM(data_length + index_length) FROM information_schema.TABLES WHERE table_schema=%s AND table_name LIKE %s', DB_NAME, $wpdb->esc_like($wpdb->prefix) . '%')); };
    $antes = $tam();
    if (!$hacer) return array('cuentas' => $cuentas, 'tamano' => $antes);
    foreach (array_chunk($revViejas, 500) as $t) foreach ($t as $id) wp_delete_post_revision((int)$id);
    foreach ($wpdb->get_col("SELECT ID FROM $p WHERE post_status='auto-draft' AND post_date < NOW() - INTERVAL 7 DAY LIMIT 5000") as $id) wp_delete_post((int)$id, true);
    $wpdb->query("DELETE c, m FROM $c c LEFT JOIN $cm m ON m.comment_id=c.comment_ID WHERE c.comment_approved IN ('spam','trash')");
    if (function_exists('delete_expired_transients')) delete_expired_transients(true);
    $wpdb->query("DELETE m FROM $pm m LEFT JOIN $p x ON x.ID=m.post_id WHERE x.ID IS NULL");
    $wpdb->query("DELETE m FROM $cm m LEFT JOIN $c x ON x.comment_ID=m.comment_id WHERE x.comment_ID IS NULL");
    foreach ($wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($wpdb->prefix) . '%')) as $t) $wpdb->query('OPTIMIZE TABLE `' . esc_sql($t) . '`');
    wp_cache_flush();
    return array('cuentas' => $cuentas, 'tamano_antes' => $antes, 'tamano_despues' => $tam());
}

/** Segundo paso tras actualizar WordPress: poner al día la base de datos (en una petición nueva, ya con el código nuevo). */
function planb_actualizar_bd(WP_REST_Request $req)
{
    planb_silencio_empezar();
    planb_cargar_admin();
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    global $wp_db_version;
    $antes = (int)get_option('db_version');
    if ($antes < (int)$wp_db_version) wp_upgrade();
    wp_cache_flush();
    planb_silencio_terminar();
    return array('wp' => $GLOBALS['wp_version'], 'bd_antes' => $antes, 'bd' => (int)get_option('db_version'));
}

/* ───────────── Quitar un plugin (desactivar y eliminar), p. ej. Duplicator por norma de Plan B ───────────── */
function planb_quitar_plugin(WP_REST_Request $req)
{
    planb_silencio_empezar();
    planb_cargar_admin();
    $archivo = (string)$req->get_param('archivo');
    $todos = get_plugins();
    if ($archivo === '' || !isset($todos[$archivo])) { planb_silencio_terminar(); return new WP_Error('no_instalado', 'Esta web no tiene ese plugin', array('status' => 409)); }
    if (strpos($archivo, 'planb-conector/') === 0) { planb_silencio_terminar(); return new WP_Error('param', 'El conector no se puede quitar desde aquí', array('status' => 400)); }
    if (is_plugin_active($archivo) || is_plugin_active_for_network($archivo)) deactivate_plugins($archivo, true, is_multisite());
    $r = delete_plugins(array($archivo));
    wp_clean_plugins_cache(true);
    $sigue = isset(get_plugins()[$archivo]);
    planb_silencio_terminar();
    if (is_wp_error($r) || $sigue) return new WP_Error('borrar', 'Se ha desactivado, pero no se pudo eliminar: ' . (is_wp_error($r) ? $r->get_error_message() : 'los archivos siguen ahí'), array('status' => 500));
    return array('quitado' => $archivo, 'nombre' => $todos[$archivo]['Name']);
}

/* ───────────── Borrar un tema que no se usa. Nunca el activo ni su tema padre. ───────────── */
function planb_quitar_tema(WP_REST_Request $req)
{
    planb_silencio_empezar();
    planb_cargar_admin();
    require_once ABSPATH . 'wp-admin/includes/theme.php';
    $slug = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$req->get_param('slug'));
    $t = $slug !== '' ? wp_get_theme($slug) : null;
    if (!$t || !$t->exists()) { planb_silencio_terminar(); return new WP_Error('no_instalado', 'Esta web no tiene ese tema', array('status' => 409)); }
    if ($slug === get_stylesheet() || $slug === get_template()) { planb_silencio_terminar(); return new WP_Error('en_uso', 'Ese tema está en uso: no se borra', array('status' => 409)); }
    $nombre = $t->get('Name');
    $r = delete_theme($slug);
    wp_clean_themes_cache();
    $sigue = wp_get_theme($slug)->exists();
    planb_silencio_terminar();
    if (is_wp_error($r) || !$r || $sigue) return new WP_Error('borrar', 'No se pudo borrar: ' . (is_wp_error($r) ? $r->get_error_message() : 'los archivos siguen ahí'), array('status' => 500));
    return array('quitado' => $slug, 'nombre' => $nombre);
}

/* ───────────── Plugin de pago: sustituir los archivos por la versión que da el panel ───────────── */
function planb_instalar_zip(WP_REST_Request $req)
{
    planb_silencio_empezar();
    $r = planb_instalar_zip_real($req);
    planb_silencio_terminar();
    return $r;
}
function planb_instalar_zip_real(WP_REST_Request $req)
{
    planb_cargar_admin();
    $url = esc_url_raw((string)$req->get_param('url'));
    $sha = strtolower((string)$req->get_param('sha256'));
    $slug = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$req->get_param('slug'));
    $tipo = $req->get_param('tipo') === 'tema' ? 'tema' : 'plugin';
    // Solo se descargan paquetes del propio panel
    if (!$url || !$slug || strlen($sha) !== 64 || !planb_host_del_panel((string)parse_url($url, PHP_URL_HOST))) {
        return new WP_Error('param', 'Paquete no válido', array('status' => 400));
    }
    $antes = null; $archivo = null; $activo = false;
    if ($tipo === 'tema') {
        $t = wp_get_theme($slug);
        if (!$t->exists()) return new WP_Error('no_instalado', 'Esta web no tiene el tema', array('status' => 409));
        $antes = $t->get('Version'); $activo = (get_stylesheet() === $slug || get_template() === $slug);
    } else {
        foreach (get_plugins() as $f => $p) if (strpos($f, $slug . '/') === 0) { $antes = $p['Version']; $archivo = $f; $activo = is_plugin_active($f); }
        if (!$archivo) return new WP_Error('no_instalado', 'Esta web no tiene el plugin', array('status' => 409));
    }
    $tmp = download_url($url, 300);
    if (is_wp_error($tmp)) return new WP_Error('descarga', 'No se pudo descargar: ' . $tmp->get_error_message(), array('status' => 502));
    if (!hash_equals($sha, hash_file('sha256', $tmp))) { @unlink($tmp); return new WP_Error('hash', 'El archivo descargado no coincide', array('status' => 409)); }
    // 1.7.22: además, tiene que estar en la lista pública de huellas (GitHub), que no depende del servidor del panel
    $fueraLista = false;
    if ($tipo === 'plugin' && $slug === 'planb-conector') {
        $mal = planb_zip_conector_ok($tmp);
        if ($mal !== '') {
            @unlink($tmp);
            planb_apuntar('seguridad', 'actualización del conector rechazada', $mal);
            return new WP_Error(strpos($mal, 'sin_huella') === 0 ? 'sin_huella' : 'huella', 'Conector no instalado (' . $mal . ')', array('status' => 409));
        }
    } else {
        $h = planb_huellas();
        $enLista = $h && isset($h['plugins'][$sha]);
        if (!$enLista && $h) { $h = planb_huellas(true); $enLista = $h && isset($h['plugins'][$sha]); }
        if (!$enLista) {
            $estricto = !$h || !empty($h['politica']['solo_lista_plugins']);
            if ($estricto && $h) { @unlink($tmp); planb_apuntar('seguridad', 'plugin rechazado (no está en la lista)', $slug); return new WP_Error('huella', 'Paquete no instalado: no está en la lista pública de huellas', array('status' => 409)); }
            $fueraLista = true;
            planb_apuntar('seguridad', 'plugin instalado fuera de la lista de huellas', $slug . ' ' . substr($sha, 0, 12));
        }
    }
    $up = $tipo === 'tema' ? new Theme_Upgrader(new Planb_Piel_Silenciosa()) : new Plugin_Upgrader(new Planb_Piel_Silenciosa());
    if (version_compare($GLOBALS['wp_version'], '5.5', '>=')) {
        $r = $up->install($tmp, array('overwrite_package' => true));
    } else {
        // WordPress antiguo: se quita la carpeta y se instala de nuevo (los datos y ajustes están en la base de datos)
        planb_borrar_arbol(($tipo === 'tema' ? get_theme_root() : WP_PLUGIN_DIR) . '/' . $slug);
        $r = $up->install($tmp);
    }
    @unlink($tmp);
    if (is_wp_error($r) || !$r) return new WP_Error('instalar', 'No se pudo instalar: ' . (is_wp_error($r) ? $r->get_error_message() : implode(' ', $up->skin->msgs)), array('status' => 500));
    $despues = null;
    if ($tipo === 'tema') {
        wp_clean_themes_cache();
        $despues = wp_get_theme($slug)->get('Version');
    } else {
        wp_clean_plugins_cache(true);
        if ($activo && !is_plugin_active($archivo)) activate_plugin($archivo, '', false, true);
        foreach (get_plugins() as $f => $p) if ($f === $archivo) $despues = $p['Version'];
        $activo = $activo ? is_plugin_active($archivo) : false;
    }
    if ($slug === 'planb-conector') delete_option('planb_huella_propia');
    return array('antes' => $antes, 'despues' => $despues, 'activo' => $activo, 'fuera_de_lista' => $fueraLista);
}

/*
 * Licencias: el panel manda la clave y aquí se activa con el sistema propio de cada fabricante.
 * Devuelve 'activada' (comprobado), 'guardada' (puesta, el fabricante la valida después) o 'manual' (hay que hacerlo en su web).
 */
function planb_licencia(WP_REST_Request $req)
{
    planb_silencio_empezar();
    planb_cargar_admin();
    $slug = preg_replace('/[^a-zA-Z0-9._-]/', '', (string)$req->get_param('slug'));
    $clave = trim((string)$req->get_param('clave'));
    $usuario = trim((string)$req->get_param('usuario'));
    $r = array('resultado' => 'manual', 'detalle' => 'Este plugin no se puede activar desde fuera: pega la licencia en su pantalla de ajustes.');
    try {
        if ($clave === '') $r = array('resultado' => 'error', 'detalle' => 'Falta la licencia');
        elseif ($slug === 'advanced-custom-fields-pro') {
            if (function_exists('acf_pro_activate_license')) {
                $x = acf_pro_activate_license($clave, true);
                $ok = function_exists('acf_pro_get_license_key') && acf_pro_get_license_key() === $clave;
                $r = array('resultado' => $ok ? 'activada' : 'error', 'detalle' => $ok ? 'ACF PRO activado' : 'ACF no la aceptó: ' . (is_wp_error($x) ? $x->get_error_message() : wp_json_encode($x)));
            } else {
                update_option('acf_pro_license', base64_encode(serialize(array('key' => $clave, 'url' => home_url()))));
                $r = array('resultado' => 'guardada', 'detalle' => 'Licencia guardada en ACF (versión antigua)');
            }
        } elseif ($slug === 'elementor-pro' && class_exists('\\ElementorPro\\License\\API')) {
            $d = \ElementorPro\License\API::activate_license($clave);
            if (is_wp_error($d) || empty($d['success'])) $r = array('resultado' => 'error', 'detalle' => 'Elementor no la aceptó: ' . (is_wp_error($d) ? $d->get_error_message() : (isset($d['error']) ? $d['error'] : 'sin respuesta')));
            else {
                if (class_exists('\\ElementorPro\\License\\Admin')) \ElementorPro\License\Admin::set_license_key($clave);
                if (method_exists('\\ElementorPro\\License\\API', 'set_license_data')) \ElementorPro\License\API::set_license_data($d);
                $r = array('resultado' => 'activada', 'detalle' => 'Elementor Pro activado');
            }
        } elseif ($slug === 'gravityforms' && class_exists('GFFormsModel') && method_exists('GFFormsModel', 'save_key')) {
            GFFormsModel::save_key($clave);
            $r = array('resultado' => 'guardada', 'detalle' => 'Licencia guardada en Gravity Forms');
        } elseif (in_array($slug, array('Divi', 'Extra', 'divi-builder', 'bloom', 'monarch'), true)) {
            if ($usuario === '') $r = array('resultado' => 'error', 'detalle' => 'Elegant Themes necesita también el nombre de usuario');
            else {
                $o = (array)get_option('et_automatic_updates_options', array());
                $o['username'] = $usuario; $o['api_key'] = $clave;
                update_option('et_automatic_updates_options', $o);
                $r = array('resultado' => 'guardada', 'detalle' => 'Usuario y API key guardados (Elegant Themes)');
            }
        }
    } catch (Exception $e) { $r = array('resultado' => 'error', 'detalle' => $e->getMessage()); }
    catch (Error $e) { $r = array('resultado' => 'error', 'detalle' => $e->getMessage()); }
    planb_silencio_terminar();
    return $r;
}

/**
 * Tablas que el clon de prueba copia VACÍAS (solo estructura): de usar y tirar, no cambian si la web se ve bien o no,
 * y son las que más pesan en una tienda. NUNCA incluye usuarios, pedidos ni contenido. Jesús/Andrés, 23/11/2026.
 */
function planb_tabla_clon_vacia($suf)
{
    $exactas = array(
        'woocommerce_sessions', 'wc_sessions',                                   // carritos y sesiones de clientes
        'actionscheduler_actions', 'actionscheduler_claims', 'actionscheduler_groups', 'actionscheduler_logs', // cola de tareas de WooCommerce (lo más gordo)
        'wc_admin_notes', 'wc_admin_note_actions', 'wc_download_log', 'woocommerce_api_keys_log', // avisos y registros de WooCommerce
        'redirection_404',                                                        // registro de páginas no encontradas (Redirection)
    );
    if (in_array($suf, $exactas, true)) return true;
    if (preg_match('/(_logs?|_events?|_event_log|_activity|_hits|_stats|_statistics)$/', $suf)) return true; // cualquier tabla de logs/estadísticas de plugins
    if (strpos($suf, 'statistics_') === 0 || strpos($suf, 'wfhits') === 0 || strpos($suf, 'wflogins') === 0) return true; // WP-Statistics y registros de Wordfence
    return false;
}

/* ───────────── Clon de prueba (misma suscripción, carpeta y tablas aparte) ───────────── */
function planb_clonar(WP_REST_Request $req)
{
    @set_time_limit(1800);
    global $wpdb;
    $carpeta = preg_replace('/[^a-z0-9-]/', '', (string)$req->get_param('carpeta'));
    $prefijo = preg_replace('/[^a-z0-9_]/', '', (string)$req->get_param('prefijo'));
    $url = esc_url_raw((string)$req->get_param('url'));
    $llave = preg_replace('/[^a-f0-9]/', '', (string)$req->get_param('llave')); // 1.7.25 (auditoría 2.9): copia de pruebas privada
    $dentro = (bool)$req->get_param('dentro'); // sin API de Plesk: el clon va en una carpeta DENTRO de la web (https://dominio/planb-clon-xxxx/)
    if (strpos($carpeta, 'planb-clon') !== 0 || strpos($prefijo, 'pbc') !== 0 || !$url) return new WP_Error('param', 'Parámetros no válidos', array('status' => 400));
    $raiz = rtrim(ABSPATH, '/');
    $destino = ($dentro ? $raiz : dirname($raiz)) . '/' . $carpeta;
    if (is_dir($destino)) planb_borrar_arbol($destino);
    wp_mkdir_p($destino);
    @chmod($destino, 0755);
    // Archivos (sin subidas: el clon las enlaza al original para ahorrar espacio)
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($raiz, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    foreach ($it as $f) {
        $rel = ltrim(str_replace('\\', '/', substr($f->getPathname(), strlen($raiz))), '/');
        if ($rel === '' || planb_excluido($rel . ($f->isDir() ? '/' : ''))) continue;
        $dst = $destino . '/' . $rel;
        // Permisos explícitos: en algunos hostings PHP crea los archivos sin permiso de lectura para el servidor web (→ 403)
        if ($f->isDir()) { if (!is_dir($dst)) @mkdir($dst, 0755, true); @chmod($dst, 0755); }
        else { @copy($f->getPathname(), $dst); @chmod($dst, 0644); }
    }
    // Subidas: las fotos se ENLAZAN al original (no se copian, para ahorrar espacio), pero lo que los plugins
    // GENERAN (CSS de Elementor, cachés…) se COPIA: si no, el clon reescribía el CSS de la web real con su propia
    // dirección y, al borrar el clon, la web real se quedaba sin imágenes de fondo (vallaure.es, 20/11/2026).
    if (is_dir($raiz . '/wp-content/uploads')) planb_clon_subidas($raiz . '/wp-content/uploads', $destino . '/wp-content/uploads');
    // Tablas con otro prefijo
    $tablas = $wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($wpdb->prefix) . '%'));
    foreach ($wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($prefijo) . '%')) as $vieja) $wpdb->query("DROP TABLE `$vieja`");
    foreach ($tablas as $t) {
        $n = $prefijo . substr($t, strlen($wpdb->prefix));
        $suf = substr($t, strlen($wpdb->prefix)); // nombre de la tabla sin el prefijo
        $wpdb->query("CREATE TABLE `$n` LIKE `$t`");
        // Clon afinado (Jesús/Andrés, 23/11/2026): las tablas de usar y tirar (sesiones, colas de WooCommerce, logs,
        // estadísticas) se copian VACÍAS (solo la estructura): no hacen falta para probar y son las que más pesan.
        if (planb_tabla_clon_vacia($suf)) continue;
        // Las opciones se copian menos los datos temporales (transients), que se regeneran solos y pueden pesar muchísimo.
        if ($suf === 'options') { $wpdb->query("INSERT INTO `$n` SELECT * FROM `$t` WHERE option_name NOT LIKE '\\_transient\\_%' AND option_name NOT LIKE '\\_site\\_transient\\_%'"); continue; }
        $wpdb->query("INSERT INTO `$n` SELECT * FROM `$t`");
    }
    // Las claves que llevan el prefijo dentro (roles y capacidades)
    $wpdb->query($wpdb->prepare("UPDATE `{$prefijo}options` SET option_name = REPLACE(option_name, %s, %s) WHERE option_name LIKE %s", $wpdb->prefix, $prefijo, $wpdb->esc_like($wpdb->prefix) . '%'));
    $wpdb->query($wpdb->prepare("UPDATE `{$prefijo}usermeta` SET meta_key = REPLACE(meta_key, %s, %s) WHERE meta_key LIKE %s", $wpdb->prefix, $prefijo, $wpdb->esc_like($wpdb->prefix) . '%'));
    $wpdb->query($wpdb->prepare("UPDATE `{$prefijo}options` SET option_value=%s WHERE option_name IN ('siteurl','home')", untrailingslashit($url)));
    // El clon no debe enviar correos ni ejecutar tareas programadas
    $wpdb->query("UPDATE `{$prefijo}options` SET option_value='0' WHERE option_name='blog_public'");
    // wp-config del clon
    $cfg = @file_get_contents($raiz . '/wp-config.php');
    if ($cfg === false) $cfg = @file_get_contents(dirname($raiz) . '/wp-config.php');
    if ($cfg === false) return new WP_Error('config', 'No se encontró wp-config.php', array('status' => 500));
    $cfg = preg_replace('/\$table_prefix\s*=\s*[\'"][^\'"]*[\'"]\s*;/', "\$table_prefix = '$prefijo';", $cfg);
    $extra = "define('WP_HOME', '" . addslashes(untrailingslashit($url)) . "');\ndefine('WP_SITEURL', '" . addslashes(untrailingslashit($url)) . "');\ndefine('DISABLE_WP_CRON', true);\ndefine('PLANB_ES_CLON', true);\n";
    if (strlen($llave) >= 32) {
        // Solo entra quien abre el enlace con la llave (queda una cookie 7 días), las llamadas a la API del conector (que
        // comprueba su firma) y,
        // durante los primeros 15 minutos, las comprobaciones automáticas. Para todos los demás: 403.
        $extra .= "if (PHP_SAPI !== 'cli' && !defined('WP_CLI')) { \$pbL = '" . $llave . "'; \$pbOk = time() < " . (time() + 900) . " || (!empty(\$_SERVER['HTTP_X_PLANB_FIRMA']) && strpos(urldecode((string)\$_SERVER['REQUEST_URI']), 'planb/v1/') !== false)"
            . " || (isset(\$_COOKIE['planb_clon']) && hash_equals(\$pbL, (string)\$_COOKIE['planb_clon']));"
            . " if (isset(\$_GET['planb_clon']) && hash_equals(\$pbL, (string)\$_GET['planb_clon'])) { \$pbOk = true; setcookie('planb_clon', \$pbL, time() + 7 * 86400, '/', '', !empty(\$_SERVER['HTTPS']), true); }"
            . " if (!\$pbOk) { http_response_code(403); header('X-Robots-Tag: noindex'); exit('Copia de pruebas privada. Abre el enlace que te ha dado tu agencia.'); } }\n";
    }
    $cfg = preg_replace('/<\?php/', "<?php\n" . $extra, $cfg, 1);
    file_put_contents($destino . '/wp-config.php', $cfg);
    file_put_contents($destino . '/robots.txt', "User-agent: *\nDisallow: /\n");
    @chmod($destino . '/wp-config.php', 0644); @chmod($destino . '/robots.txt', 0644);
    if ($dentro) {
        // Reglas propias de la carpeta: WordPress del clon, sin pasar por el de la web real, y oculto a buscadores
        $base = '/' . trim((string)parse_url($url, PHP_URL_PATH), '/') . '/';
        file_put_contents($destino . '/.htaccess', "# Clon de prueba del Panel Plan B (se borra solo)\n<IfModule mod_headers.c>\nHeader set X-Robots-Tag \"noindex, nofollow\"\n</IfModule>\n"
            . "DirectoryIndex index.php index.html\n"
            . "<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase $base\nRewriteRule ^$ index.php [L]\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . {$base}index.php [L]\n</IfModule>\n");
        @chmod($destino . '/.htaccess', 0644);
    }
    return array('carpeta' => $destino, 'prefijo' => $prefijo, 'tablas' => count($tablas));
}

/** Subidas del clon: carpetas de años (2024, 2025…) y las muy grandes, enlazadas; todo lo demás, copiado aparte. */
function planb_clon_subidas($origen, $destino)
{
    if (is_link($destino)) @unlink($destino);
    wp_mkdir_p($destino); @chmod($destino, 0755);
    foreach ((array)@scandir($origen) as $n) {
        if ($n === '.' || $n === '..' || strpos($n, 'planb-') === 0) continue;
        $o = $origen . '/' . $n; $d = $destino . '/' . $n;
        if (is_dir($o) && (preg_match('/^\d{4}$/', $n) || $n === 'sites' || planb_tamano_dir($o, 150 * 1048576) > 150 * 1048576)) { @symlink($o, $d); continue; }
        if (is_file($o)) { @copy($o, $d); @chmod($d, 0644); continue; }
        if (!is_dir($o)) continue;
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($o, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
        @mkdir($d, 0755, true);
        foreach ($it as $f) {
            $dst = $d . '/' . ltrim(str_replace('\\', '/', substr($f->getPathname(), strlen($o))), '/');
            if ($f->isDir()) { if (!is_dir($dst)) @mkdir($dst, 0755, true); }
            else { @copy($f->getPathname(), $dst); @chmod($dst, 0644); }
        }
    }
}

/** Tamaño de una carpeta, parando en cuanto pasa del límite (para no recorrer carpetas enormes). */
function planb_tamano_dir($d, $limite)
{
    $t = 0;
    try { foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS)) as $f) { $t += (int)$f->getSize(); if ($t > $limite) break; } } catch (Exception $e) {}
    return $t;
}

/* ───────────── Paquetes de plugins de pago para la copia de prueba (1.7.7) ─────────────
 * Un plugin de pago solo se actualiza en la web que tiene la licencia. La copia de prueba tiene otra dirección y no
 * puede. Antes de hacer la copia, la web REAL descarga con su licencia la versión nueva de cada plugin y la guarda en
 * una carpeta privada con nombre imposible de adivinar; la copia la hereda y la instala desde ahí. Al terminar se borra.
 */
function planb_paquetes_dir($crear = false)
{
    foreach ((array)glob(WP_CONTENT_DIR . '/planb-paquetes-*', GLOB_ONLYDIR) as $d) return $d;
    if (!$crear) return '';
    $d = WP_CONTENT_DIR . '/planb-paquetes-' . bin2hex(random_bytes(16));
    wp_mkdir_p($d);
    @file_put_contents($d . '/index.php', "<?php // Silencio\n");
    @file_put_contents($d . '/.htaccess', "Require all denied\nDeny from all\n");
    return $d;
}

/** Zip guardado para un plugin («carpeta/archivo.php»), o vacío. */
function planb_paquete_local($archivo)
{
    $d = planb_paquetes_dir();
    if ($d === '') return '';
    $slug = sanitize_file_name(dirname((string)$archivo));
    $f = $d . '/' . $slug . '.zip';
    return is_file($f) ? $f : '';
}

/** En la web REAL: descarga con su licencia la versión nueva de los plugins pedidos que tengan descarga. */
function planb_preparar_paquetes(WP_REST_Request $req)
{
    planb_silencio_empezar();
    planb_cargar_admin();
    planb_borrar_paquetes_dir();
    wp_update_plugins();
    $lista = get_site_transient('update_plugins');
    $res = array('preparados' => array(), 'sin_descarga' => array());
    foreach ((array)$req->get_param('plugins') as $p) {
        $p = (string)$p;
        $pkg = isset($lista->response[$p]->package) ? (string)$lista->response[$p]->package : '';
        if ($pkg === '') { $res['sin_descarga'][] = $p; continue; }
        $tmp = download_url($pkg, 300);
        if (is_wp_error($tmp)) { $res['sin_descarga'][] = $p . ' (' . $tmp->get_error_message() . ')'; continue; }
        $d = planb_paquetes_dir(true);
        $dst = $d . '/' . sanitize_file_name(dirname($p)) . '.zip';
        if (!@rename($tmp, $dst)) { @copy($tmp, $dst); @unlink($tmp); }
        @chmod($dst, 0640);
        $res['preparados'][] = $p;
    }
    planb_silencio_terminar();
    return $res;
}

function planb_borrar_paquetes_dir()
{
    foreach ((array)glob(WP_CONTENT_DIR . '/planb-paquetes-*', GLOB_ONLYDIR) as $d) planb_borrar_arbol($d);
}

function planb_borrar_paquetes(WP_REST_Request $req)
{
    planb_borrar_paquetes_dir();
    return array('ok' => true);
}

function planb_borrar_clon(WP_REST_Request $req)
{
    global $wpdb;
    $carpeta = preg_replace('/[^a-z0-9-]/', '', (string)$req->get_param('carpeta'));
    $prefijo = preg_replace('/[^a-z0-9_]/', '', (string)$req->get_param('prefijo'));
    if (strpos($carpeta, 'planb-clon') !== 0 || strpos($prefijo, 'pbc') !== 0 || $prefijo === $wpdb->prefix) return new WP_Error('param', 'Parámetros no válidos', array('status' => 400));
    $destino = ($req->get_param('dentro') ? rtrim(ABSPATH, '/') : dirname(rtrim(ABSPATH, '/'))) . '/' . $carpeta;
    if (is_link($destino . '/wp-content/uploads')) @unlink($destino . '/wp-content/uploads');
    planb_borrar_arbol($destino);
    foreach ($wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($prefijo) . '%')) as $t) $wpdb->query("DROP TABLE `$t`");
    planb_borrar_paquetes_dir();
    return array('ok' => true, 'css_reparado' => planb_reparar_css_clon());
}

/* ───────────── PHP: consulta ligera (el panel la usa cada 5 minutos para ver si alguien cambió el PHP en Plesk) ───────────── */
function planb_php(WP_REST_Request $req)
{
    return array('php' => PHP_VERSION, 'wp' => $GLOBALS['wp_version'], 'fatales' => planb_errores_recientes(20));
}

/** Errores graves de PHP en el registro de la web en los últimos $min minutos (si el registro se puede leer). */
function planb_errores_recientes($min)
{
    $f = defined('WP_DEBUG_LOG') && is_string(WP_DEBUG_LOG) ? WP_DEBUG_LOG : (string)ini_get('error_log');
    if (!$f && is_file(WP_CONTENT_DIR . '/debug.log')) $f = WP_CONTENT_DIR . '/debug.log';
    if (!$f || !is_readable($f) || filemtime($f) < time() - $min * 60) return array();
    $h = fopen($f, 'r'); $tam = filesize($f); fseek($h, max(0, $tam - 200000)); $txt = stream_get_contents($h); fclose($h);
    $o = array();
    foreach (array_reverse(explode("\n", $txt)) as $l) {
        if (!preg_match('/^\[([^\]]+)\].*PHP (Fatal error|Parse error)/', $l, $m)) continue;
        $t = strtotime($m[1]); if ($t && $t < time() - $min * 60) break;
        $o[] = mb_substr(trim($l), 0, 300); if (count($o) >= 5) break;
    }
    return $o;
}

/* ───────────── Revisión del código para una versión de PHP ─────────────
 * Sin API de Plesk el clon no puede cambiar de PHP, así que se revisa el código de lo que está ACTIVO
 * (plugins, tema y WordPress) buscando lo que deja de funcionar en la versión nueva. */
function planb_compat(WP_REST_Request $req)
{
    @set_time_limit(600);
    planb_cargar_admin();
    global $wp_version;
    $hacia = preg_replace('/[^0-9.]/', '', (string)$req->get_param('hacia'));
    if (!$hacia) return new WP_Error('param', 'Falta la versión', array('status' => 400));
    $bloqueos = array(); $avisos = array(); $revisados = 0;
    // 1) WordPress: versión mínima que funciona bien con cada PHP
    $wpMin = array('8.0' => '5.6', '8.1' => '5.9', '8.2' => '6.1', '8.3' => '6.4', '8.4' => '6.7', '8.5' => '6.9');
    $rama = implode('.', array_slice(explode('.', $hacia), 0, 2));
    if (isset($wpMin[$rama]) && version_compare($wp_version, $wpMin[$rama], '<')) $bloqueos[] = "WordPress $wp_version es demasiado antiguo para PHP $rama (mínimo {$wpMin[$rama]})";
    // 2) Funciones que ya no existen en la versión nueva (desaparecen → error grave) y las que avisan
    $quitadas = array(
        '7.0' => array('mysql_connect', 'mysql_query', 'mysql_fetch_array', 'mysql_fetch_assoc', 'mysql_real_escape_string', 'mysql_num_rows', 'mysql_select_db', 'mysql_close', 'mysql_error', 'ereg', 'eregi', 'ereg_replace', 'eregi_replace', 'split', 'spliti', 'call_user_method', 'call_user_method_array', 'set_magic_quotes_runtime', 'set_socket_blocking', 'mcrypt_generic_end', 'mcrypt_ecb', 'mcrypt_cbc'),
        '7.2' => array('mcrypt_encrypt', 'mcrypt_decrypt', 'mcrypt_create_iv', 'mcrypt_get_iv_size', 'mcrypt_module_open'),
        '8.0' => array('each', 'create_function', 'money_format', 'get_magic_quotes_gpc', 'get_magic_quotes_runtime', 'fgetss', 'gzgetss', 'image2wbmp', 'hebrevc', 'convert_cyr_string', 'restore_include_path', 'ezmlm_hash', 'is_real', 'mbregex_encoding', 'mbereg', 'mberegi', 'mbereg_replace', 'mbsplit', 'jpeg2wbmp', 'png2wbmp', 'read_exif_data', 'ldap_sort'),
        '8.5' => array('mhash', 'mhash_count', 'mhash_get_block_size', 'mhash_get_hash_name', 'mhash_keygen_s2k'),
    );
    $avisan = array('8.1' => array('strftime', 'gmstrftime', 'date_sunrise', 'date_sunset', 'mhash'), '8.2' => array('utf8_encode', 'utf8_decode'), '8.4' => array('mysqli_ping', 'mysqli_refresh', 'mysqli_kill'));
    $muertas = array(); $viejas = array();
    foreach ($quitadas as $v => $fs) if (version_compare($hacia, $v, '>=')) foreach ($fs as $f) $muertas[$f] = $v;
    foreach ($avisan as $v => $fs) if (version_compare($hacia, $v, '>=')) foreach ($fs as $f) $viejas[$f] = $v;
    $carpetas = array();
    foreach ((array)get_option('active_plugins', array()) as $f) {
        $d = WP_PLUGIN_DIR . '/' . dirname($f);
        $datos = get_plugin_data(WP_PLUGIN_DIR . '/' . $f, false, false);
        $carpetas[] = array('Plugin ' . $datos['Name'] . ' ' . $datos['Version'], dirname($f) === '.' ? WP_PLUGIN_DIR . '/' . $f : $d, (isset($datos['RequiresPHP']) ? $datos['RequiresPHP'] : ''));
    }
    foreach (array_unique(array(get_stylesheet(), get_template())) as $t) {
        $th = wp_get_theme($t);
        $carpetas[] = array('Tema ' . $th->get('Name') . ' ' . $th->get('Version'), $th->get_stylesheet_directory(), (string)$th->get('RequiresPHP'));
    }
    foreach ($carpetas as list($nombre, $dir, $req)) {
        $problemas = array(); $avs = array(); $cifrado = false;
        $archivos = is_file($dir) ? array($dir) : planb_php_de($dir, 4000);
        foreach ($archivos as $a) {
            $codigo = @file_get_contents($a, false, null, 0, 1500000);
            if ($codigo === false) continue;
            $revisados++;
            $cabeza = substr($codigo, 0, 2000); // los archivos cifrados empiezan con el cargador de ionCube o SourceGuardian
            if (preg_match('/^<\?php\s*\/\/[0-9a-f]{2,}/i', $cabeza) && stripos($cabeza, 'ioncube') !== false || preg_match('/^<\?php\s*(\/\*|\/\/)?\s*SourceGuardian/i', $cabeza)) { $cifrado = true; continue; }
            $tok = @token_get_all($codigo);
            $n = count($tok);
            for ($i = 0; $i < $n; $i++) {
                if (!is_array($tok[$i]) || $tok[$i][0] !== T_STRING) continue;
                $nom = strtolower($tok[$i][1]);
                if (!isset($muertas[$nom]) && !isset($viejas[$nom])) continue;
                // ¿es una llamada a función global? (siguiente símbolo "(" y antes no hay ->, ::, function ni new)
                $j = $i + 1; while ($j < $n && is_array($tok[$j]) && $tok[$j][0] === T_WHITESPACE) $j++;
                if ((isset($tok[$j]) ? $tok[$j] : '') !== '(') continue;
                $k = $i - 1; while ($k >= 0 && is_array($tok[$k]) && $tok[$k][0] === T_WHITESPACE) $k--;
                $prev = isset($tok[$k]) ? $tok[$k] : '';
                if (is_array($prev) && in_array($prev[0], array(T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW), true)) continue;
                if (is_array($prev) && defined('T_NULLSAFE_OBJECT_OPERATOR') && $prev[0] === T_NULLSAFE_OBJECT_OPERATOR) continue;
                $donde = str_replace(WP_CONTENT_DIR, 'wp-content', $a) . ':' . $tok[$i][2];
                // si el plugin comprueba antes si existe la función (function_exists), no rompe
                if (preg_match('/function_exists\s*\(\s*[\'"]' . preg_quote($nom, '/') . '[\'"]/i', $codigo)) continue;
                if (isset($muertas[$nom])) $problemas[$nom] = "$nom() desaparece en PHP {$muertas[$nom]} ($donde)";
                else $avs[$nom] = "$nom() está obsoleta desde PHP {$viejas[$nom]} ($donde)";
            }
        }
        if ($req && version_compare($req, $hacia, '>')) $problemas[] = "pide como mínimo PHP $req";
        if ($problemas) $bloqueos[] = $nombre . ': ' . implode('; ', array_slice($problemas, 0, 3));
        if ($avs) $avisos[] = $nombre . ': ' . implode('; ', array_slice($avs, 0, 2)) . ' (solo avisa, no rompe la web)';
        if ($cifrado) $avisos[] = $nombre . ': tiene código cifrado (ionCube) y no se puede revisar; comprobar que el proveedor da versión para PHP ' . $rama;
    }
    return array('hacia' => $hacia, 'php_actual' => PHP_VERSION, 'wp' => $wp_version, 'revisados' => $revisados, 'componentes' => count($carpetas), 'bloqueos' => $bloqueos, 'avisos' => $avisos, 'ok' => !$bloqueos);
}

/** Archivos .php de una carpeta (sin las de pruebas ni librerías de desarrollo). */
function planb_php_de($dir, $max)
{
    $o = array();
    if (!is_dir($dir)) return $o;
    $it = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), function ($f) {
        return !($f->isDir() && in_array(strtolower($f->getFilename()), array('tests', 'test', 'node_modules', '.git', 'docs', 'examples'), true));
    }));
    foreach ($it as $f) { if (substr($f->getFilename(), -4) === '.php') { $o[] = $f->getPathname(); if (count($o) >= $max) break; } }
    return $o;
}

/* En el clon: nada de correos a clientes reales */
if (defined('PLANB_ES_CLON') && PLANB_ES_CLON) {
    add_filter('pre_wp_mail', '__return_false');
}

/* Pantalla de estado en Ajustes */
add_action('admin_menu', function () {
    add_options_page('Plan B Conector', 'Plan B Conector', 'manage_options', 'planb-conector', function () {
        echo '<div class="wrap"><h1>Plan B Conector</h1><p>Esta web se mantiene desde el Panel Plan B.</p>';
        echo '<p><strong>Estado del alta:</strong> ' . esc_html((string)get_option('planb_registro', 'pendiente')) . '</p>';
        echo '<p><strong>Versión:</strong> ' . esc_html(PLANB_CONECTOR_VERSION) . '</p></div>';
    });
});


/* ───────────── Copias completas (para Google Drive, desde 1.5.0) ─────────────
 * Archivos de la web (imágenes incluidas) + base de datos en un solo zip, en wp-content/planb-copias (protegida).
 * El panel la descarga con un enlace de un solo uso, la sube a Drive y la borra de aquí.
 */
function planb_dir_copias()
{
    $d = WP_CONTENT_DIR . '/planb-copias';
    if (!is_dir($d)) {
        wp_mkdir_p($d);
        @file_put_contents($d . '/.htaccess', "Require all denied\nDeny from all\n");
        @file_put_contents($d . '/index.php', '<?php // silencio');
        @file_put_contents($d . '/web.config', '<configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>');
    }
    return $d;
}
function planb_volcar_bd($sqlf)
{
    global $wpdb;
    $h = fopen($sqlf, 'w');
    fwrite($h, "SET NAMES utf8mb4;\nSET foreign_key_checks=0;\n");
    $tablas = $wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($wpdb->prefix) . '%'));
    foreach ($tablas as $t) {
        $crea = $wpdb->get_row("SHOW CREATE TABLE `$t`", ARRAY_N);
        fwrite($h, "DROP TABLE IF EXISTS `$t`;\n" . $crea[1] . ";\n");
        $off = 0;
        do {
            $filas = $wpdb->get_results("SELECT * FROM `$t` LIMIT $off, 500", ARRAY_A);
            foreach ($filas as $fila) {
                $vals = array();
                foreach ($fila as $v) $vals[] = $v === null ? 'NULL' : "'" . $wpdb->remove_placeholder_escape(esc_sql($v)) . "'"; // sin el escape de «%» de $wpdb (cambia en cada petición y rompería los datos al restaurar)
                fwrite($h, "INSERT INTO `$t` VALUES (" . implode(',', $vals) . ");\n");
            }
            $off += 500;
        } while (count($filas) === 500);
    }
    fwrite($h, "SET foreign_key_checks=1;\n");
    fclose($h);
    return count($tablas);
}
function planb_copia_completa(WP_REST_Request $req)
{
    @set_time_limit(3600); @ignore_user_abort(true);
    if (!class_exists('ZipArchive')) return new WP_Error('sin_zip', 'El servidor no tiene ZipArchive', array('status' => 500));
    $base = planb_dir_copias();
    foreach (glob($base . '/*.zip') as $vieja) @unlink($vieja); // nunca se acumulan
    foreach (glob($base . '/*.sql') as $vieja) @unlink($vieja);
    $id = date('Ymd-His') . '-' . planb_aleatorio(32);
    $sql = $base . '/' . $id . '.sql';
    $tablas = planb_volcar_bd($sql);
    $zipf = $base . '/' . $id . '.zip';
    $zip = new ZipArchive();
    if ($zip->open($zipf, ZipArchive::CREATE) !== true) return new WP_Error('zip', 'No se pudo crear el zip', array('status' => 500));
    $zip->addFile($sql, 'base-de-datos.sql');
    $raiz = rtrim(ABSPATH, '/');
    $fuera = array('.git/', '.svn/', 'node_modules/', 'wp-content/cache/', 'wp-content/planb-puntos/', 'wp-content/planb-copias/', 'wp-content/upgrade/', 'wp-content/backups', 'wp-content/updraft', 'wp-content/ai1wm-backups', 'wp-content/backup-db', 'wp-content/wflogs', 'wp-content/et-cache', 'wp-snapshots/', 'planb-clon');
    $sinComprimir = '#\.(jpe?g|png|gif|webp|avif|mp4|mov|webm|mp3|zip|gz|pdf|woff2?)$#i';
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($raiz, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
    $n = 0;
    foreach ($it as $f) {
        $rel = ltrim(str_replace('\\', '/', substr($f->getPathname(), strlen($raiz))), '/');
        if ($rel === '') continue;
        $relD = $rel . ($f->isDir() ? '/' : '');
        $saltar = false;
        foreach ($fuera as $x) if (strpos($relD, $x) === 0) { $saltar = true; break; }
        if ($saltar) continue;
        if ($f->isDir()) { $zip->addEmptyDir('web/' . $rel); continue; }
        if (!$f->isReadable()) continue;
        $zip->addFile($f->getPathname(), 'web/' . $rel);
        // Imágenes, vídeos y archivos ya comprimidos se guardan tal cual: mucho más rápido y casi igual de pequeño
        if (method_exists($zip, 'setCompressionName') && preg_match($sinComprimir, $rel)) $zip->setCompressionName('web/' . $rel, ZipArchive::CM_STORE);
        $n++;
    }
    $zip->addFromString('LEEME.txt', 'Copia completa de ' . home_url() . ' del ' . date('d/m/Y H:i') . "\r\nweb/: archivos de la web · base-de-datos.sql: la base de datos (prefijo " . $GLOBALS['wpdb']->prefix . ")\r\nHecha por el Panel Plan B.");
    $ok = $zip->close();
    @unlink($sql);
    if (!$ok || !is_file($zipf)) return new WP_Error('zip', 'No se pudo cerrar el zip (¿falta espacio?)', array('status' => 500));
    return array('copia' => $id, 'archivos' => $n, 'tablas' => $tablas, 'bytes' => filesize($zipf), 'sha256' => hash_file('sha256', $zipf));
}
function planb_copia_enlace(WP_REST_Request $req)
{
    $id = preg_replace('/[^0-9a-z-]/', '', (string)$req->get_param('copia'));
    if (!$id || !is_file(planb_dir_copias() . '/' . $id . '.zip')) return new WP_Error('no_copia', 'Copia no encontrada', array('status' => 404));
    $t = planb_aleatorio(48);
    set_transient('planb_copia_' . $t, $id, 3600);
    return array('url' => add_query_arg('t', $t, rest_url('planb/v1/copia-bajar')));
}
function planb_copia_bajar(WP_REST_Request $req)
{
    $t = preg_replace('/[^0-9a-zA-Z]/', '', (string)$req->get_param('t'));
    $id = $t ? get_transient('planb_copia_' . $t) : false;
    if (!$id) return new WP_Error('no', 'Enlace caducado', array('status' => 403));
    delete_transient('planb_copia_' . $t); // un solo uso
    $f = planb_dir_copias() . '/' . $id . '.zip';
    if (!is_file($f)) return new WP_Error('no_copia', 'Copia no encontrada', array('status' => 404));
    @set_time_limit(3600);
    while (ob_get_level()) ob_end_clean();
    header('Content-Type: application/zip');
    header('Content-Length: ' . filesize($f));
    header('Content-Disposition: attachment; filename="copia.zip"');
    $h = fopen($f, 'rb');
    while (!feof($h)) { echo fread($h, 1048576); flush(); }
    fclose($h);
    exit;
}
function planb_borrar_copia(WP_REST_Request $req)
{
    $id = preg_replace('/[^0-9a-z-]/', '', (string)$req->get_param('copia'));
    if ($id) { @unlink(planb_dir_copias() . '/' . $id . '.zip'); @unlink(planb_dir_copias() . '/' . $id . '.sql'); }
    return array('ok' => true);
}

/* Desactiva un plugin (sin borrarlo) — para fallos de seguridad graves sin arreglo (desde 1.5.1). */
function planb_desactivar_plugin(WP_REST_Request $req)
{
    planb_cargar_admin();
    $archivo = (string)$req->get_param('archivo');
    if ($archivo === '' || !isset(get_plugins()[$archivo])) return new WP_Error('no_instalado', 'Esta web no tiene ese plugin', array('status' => 409));
    if (strpos($archivo, 'planb-conector/') === 0) return new WP_Error('param', 'El conector no se desactiva', array('status' => 400));
    deactivate_plugins($archivo, true, is_multisite());
    return array('desactivado' => !is_plugin_active($archivo));
}

/* El panel puede servir los paquetes desde su dirección o desde otra del mismo dominio (p. ej. panel real y panel de pruebas). Desde 1.5.2. */
function planb_host_del_panel($host)
{
    // 1.7.21 (auditoría 1.2): solo el host EXACTO del panel (antes valía cualquier subdominio del mismo dominio)
    $mio = strtolower((string)parse_url(PLANB_PANEL_URL, PHP_URL_HOST));
    $host = strtolower((string)$host);
    if ($host === '' || $mio === '') return false;
    return $host === $mio || $host === 'www.' . $mio || 'www.' . $host === $mio;
}


/**
 * 1.7.27 · Vigilancia de cobros de la tienda (Jesús, 25/11/2026): cuándo entró el último pedido pagado, cuántos pagos han
 * fallado en las últimas 24 horas y cómo va cada forma de pago esta semana. Para que el panel avise si una tienda que vende
 * a diario deja de cobrar (pasarela caída) aunque la web abra bien. Solo números y nombres de formas de pago: ningún dato
 * de clientes.
 */
function planb_cobros(WP_REST_Request $req)
{
    if (!class_exists('WooCommerce') || !function_exists('wc_get_orders')) return array('woocommerce' => false);
    @set_time_limit(90);
    $ahora = time();
    $pagados = array('wc-processing', 'wc-completed', 'wc-on-hold');
    $n30 = wc_get_orders(array('status' => $pagados, 'date_created' => '>' . ($ahora - 30 * 86400), 'limit' => 3000, 'return' => 'ids', 'type' => 'shop_order'));
    $ult = wc_get_orders(array('status' => $pagados, 'limit' => 1, 'orderby' => 'date', 'order' => 'DESC', 'type' => 'shop_order'));
    $ultimo = null;
    if ($ult && $ult[0]->get_date_created()) $ultimo = $ult[0]->get_date_created()->getTimestamp();
    $fallidos = wc_get_orders(array('status' => array('wc-failed'), 'date_created' => '>' . ($ahora - 86400), 'limit' => 500, 'return' => 'ids', 'type' => 'shop_order'));
    $atascados = wc_get_orders(array('status' => array('wc-pending'), 'date_created' => ($ahora - 86400) . '...' . ($ahora - 3600), 'limit' => 500, 'return' => 'ids', 'type' => 'shop_order'));
    $metodos = array();
    foreach (wc_get_orders(array('status' => array('wc-processing', 'wc-completed', 'wc-on-hold', 'wc-failed', 'wc-pending'), 'date_created' => '>' . ($ahora - 7 * 86400), 'limit' => 1000, 'type' => 'shop_order')) as $o) {
        $m = (string)$o->get_payment_method_title();
        if ($m === '') $m = (string)$o->get_payment_method();
        if ($m === '') continue;
        if (!isset($metodos[$m])) $metodos[$m] = array('pagados' => 0, 'fallidos' => 0, 'ultimo_pagado' => null, 'ultimo_fallo' => null);
        $t = $o->get_date_created() ? $o->get_date_created()->getTimestamp() : 0;
        $st = $o->get_status();
        if (in_array($st, array('processing', 'completed', 'on-hold'), true)) { $metodos[$m]['pagados']++; if ($t > (int)$metodos[$m]['ultimo_pagado']) $metodos[$m]['ultimo_pagado'] = $t; }
        elseif ($st === 'failed') { $metodos[$m]['fallidos']++; if ($t > (int)$metodos[$m]['ultimo_fallo']) $metodos[$m]['ultimo_fallo'] = $t; }
    }
    $activas = array();
    if (function_exists('WC') && WC()->payment_gateways()) foreach (WC()->payment_gateways()->get_available_payment_gateways() as $g) $activas[] = (string)$g->get_title();
    return array('woocommerce' => true, 'ahora' => $ahora, 'pagados_30d' => count($n30), 'ultimo_pagado' => $ultimo, 'fallidos_24h' => count($fallidos),
        'atascados_24h' => count($atascados), 'metodos' => $metodos, 'formas_activas' => $activas);
}

/**
 * 1.7.17 · Números de la tienda WooCommerce para los informes (como Modular DS): pedidos y ventas de los últimos 30 días
 * (y de los 30 anteriores, para comparar), los productos más vendidos y los que se han quedado sin existencias.
 * Solo números y nombres de productos: ningún dato de clientes (ni nombres, ni correos, ni direcciones).
 */
function planb_tienda(WP_REST_Request $req)
{
    if (!class_exists('WooCommerce') || !function_exists('wc_get_orders')) return array('woocommerce' => false);
    @set_time_limit(120);
    $estados = array('wc-completed', 'wc-processing', 'wc-on-hold');
    $periodo = function ($desde, $hasta) use ($estados) {
        $ids = wc_get_orders(array('status' => $estados, 'date_created' => $desde . '...' . $hasta, 'limit' => 2000, 'return' => 'ids', 'type' => 'shop_order'));
        $total = 0.0; $prod = array();
        foreach ($ids as $id) {
            $o = wc_get_order($id); if (!$o) continue;
            $total += (float)$o->get_total();
            foreach ($o->get_items() as $it) { $n = $it->get_name(); $prod[$n] = (isset($prod[$n]) ? $prod[$n] : 0) + (int)$it->get_quantity(); }
        }
        arsort($prod);
        return array('pedidos' => count($ids), 'ventas' => round($total, 2), 'top' => array_slice($prod, 0, 5, true));
    };
    $hoy = current_time('timestamp');
    $ahora = $periodo(date('Y-m-d', $hoy - 29 * 86400), date('Y-m-d', $hoy));
    $antes = $periodo(date('Y-m-d', $hoy - 59 * 86400), date('Y-m-d', $hoy - 30 * 86400));
    $sin = array();
    if (function_exists('wc_get_products')) foreach (wc_get_products(array('stock_status' => 'outofstock', 'limit' => 20, 'status' => 'publish')) as $p) $sin[] = $p->get_name();
    return array('woocommerce' => true, 'moneda' => function_exists('get_woocommerce_currency') ? get_woocommerce_currency() : 'EUR', 'ahora' => $ahora, 'antes' => $antes, 'sin_existencias' => $sin, 'version' => defined('WC_VERSION') ? WC_VERSION : '');
}
