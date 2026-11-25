<?php
/*
 * VERIFICADOR DE PLAN B (se ejecuta en GitHub, fuera del servidor del panel).
 * Publica en huellas.json las huellas (sha256) de lo único que las webs de clientes pueden instalar desde el panel:
 *  · cada versión del conector de WordPress (archivo a archivo, tal como lo empaqueta el panel para actualizar);
 *  · los paquetes oficiales de los plugins y temas comprados en Envato (descargados aquí directamente de Envato).
 * Si alguien tocara el servidor del panel, lo que preparase allí no tendría su huella en esta lista y ninguna web lo instalaría.
 * No hay nada secreto en este archivo ni en huellas.json. El token de Envato solo vive en los «secrets» de GitHub.
 */
$raiz = dirname(__DIR__);
$cfg = json_decode((string)file_get_contents($raiz . '/huellas-config.json'), true);
$salida = $raiz . '/huellas.json';
$h = is_file($salida) ? (json_decode((string)file_get_contents($salida), true) ?: []) : [];
$h += ['formato' => 1, 'conector' => [], 'plugins' => [], 'envato_versiones' => []];
$h['politica'] = ['solo_lista_plugins' => !empty($cfg['solo_lista_plugins'])];

/** El texto de un archivo del conector «normalizado»: sin la dirección del panel ni las claves de alta (que cambian por descarga). */
function normalizar(string $c): string
{
    $c = preg_replace("/define\\('PLANB_CLAVE_REGISTRO', '[^']*'\\);/", "define('PLANB_CLAVE_REGISTRO', '');", $c);
    $c = preg_replace("/define\\('PLANB_TOKEN_ALTA', '[^']*'\\);/", "define('PLANB_TOKEN_ALTA', '');", $c);
    return preg_replace_callback("/define\\('PLANB_PANEL_URL', '([^']*)'\\);/", fn($m) => "define('PLANB_PANEL_URL', '" . rtrim($m[1], '/') . "');", $c);
}

// 1 · Conector: la versión que hay en el repositorio
$dir = $raiz . '/conector/planb-conector';
$p = (string)@file_get_contents($dir . '/planb-conector.php');
if (preg_match("/define\\('PLANB_CONECTOR_VERSION', '([0-9.]+)'\\)/", $p, $m)) {
    $v = $m[1]; $arch = [];
    foreach (scandir($dir) as $f) {
        if ($f[0] === '.' || is_dir($dir . '/' . $f)) continue;
        $c = (string)file_get_contents($dir . '/' . $f);
        if ($f === 'planb-conector.php') $c = normalizar(str_replace(['__PANEL_URL__', '__CLAVE_REGISTRO__', '__TOKEN_ALTA__', '__HUELLAS_URL__'], [$cfg['panel_url'], '', '', $cfg['huellas_url'] ?? 'https://raw.githubusercontent.com/JesusGil1405/planb-huellas/main/huellas.json'], $c));
        $arch[$f] = hash('sha256', $c);
    }
    ksort($arch);
    if (($h['conector'][$v]['archivos'] ?? null) !== $arch) $h['conector'][$v] = ['archivos' => $arch, 'publicado' => gmdate('c')];
    echo "Conector $v: " . count($arch) . " archivos\n";
}

// 2 · Envato: paquetes oficiales de lo comprado (solo se descarga lo que ha cambiado de versión)
$tok = getenv('ENVATO_TOKEN');
if ($tok) {
    $api = function (string $ruta) use ($tok): array {
        $ch = curl_init('https://api.envato.com' . $ruta);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60, CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $tok, 'Accept: application/json']]);
        $r = (string)curl_exec($ch); $c = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
        if ($c >= 300) throw new RuntimeException('Envato respondió ' . $c);
        return json_decode($r, true) ?: [];
    };
    $nuevos = 0;
    try {
        foreach (['wordpress-plugins' => 'wordpress_plugin', 'wordpress-themes' => 'wordpress_theme'] as $filtro => $campo) {
            for ($pag = 1; $pag <= 10; $pag++) {
                try { $r = $api('/v3/market/buyer/list-purchases?filter_by=' . $filtro . '&page=' . $pag); }
                catch (Throwable $e) { echo "Lista $filtro página $pag: " . $e->getMessage() . "\n"; break; } // 404 = no hay más páginas
                $res = (array)($r['results'] ?? []);
                foreach ($res as $x) {
                    $it = (array)($x['item'] ?? []); $id = (int)($it['id'] ?? 0);
                    if (!$id) continue;
                    $meta = (array)($it['wordpress_plugin_metadata'] ?? $it['wordpress_theme_metadata'] ?? []);
                    $ver = (string)($meta['version'] ?? $it['updated_at'] ?? '');
                    if (($h['envato_versiones'][(string)$id] ?? '') === $ver) continue; // ya tenemos la huella de esta versión
                    try { $d = $api('/v3/market/buyer/download?item_id=' . $id); }
                    catch (Throwable $e) { echo "Descarga $id: " . $e->getMessage() . "\n"; continue; }
                    $url = (string)($d[$campo] ?? $d['download_url'] ?? '');
                    if (!preg_match('#^https://#', $url)) continue;
                    $tmp = tempnam(sys_get_temp_dir(), 'env');
                    $fp = fopen($tmp, 'wb'); $ch = curl_init($url);
                    curl_setopt_array($ch, [CURLOPT_FILE => $fp, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 5, CURLOPT_TIMEOUT => 600, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS]);
                    curl_exec($ch); $c = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch); fclose($fp);
                    if ($c >= 300 || filesize($tmp) < 1000) { @unlink($tmp); continue; }
                    // El paquete tal cual y, si es el «paquete completo», cada zip instalable de dentro
                    $shas = [hash_file('sha256', $tmp)];
                    $z = new ZipArchive();
                    if ($z->open($tmp) === true) {
                        for ($i = 0; $i < $z->numFiles; $i++) { $n = (string)$z->getNameIndex($i); if (str_ends_with(strtolower($n), '.zip') && !str_starts_with($n, '__MACOSX/')) $shas[] = hash('sha256', (string)$z->getFromIndex($i)); }
                        $z->close();
                    }
                    @unlink($tmp);
                    foreach ($shas as $s) $h['plugins'][$s] = gmdate('c');
                    $h['envato_versiones'][(string)$id] = $ver;
                    $nuevos++;
                }
                if (count($res) < 1 || empty($r['next_page_url'])) break;
            }
        }
    } catch (Throwable $e) { echo 'Envato: ' . $e->getMessage() . "\n"; }
    echo "Envato: $nuevos paquetes nuevos\n";
} else echo "Envato: sin token (se omite)\n";

// Lo de más de 18 meses se quita (las webs ya no lo necesitan)
foreach ($h['plugins'] as $s => $f) if (strtotime($f) < time() - 548 * 86400) unset($h['plugins'][$s]);
ksort($h['conector'], SORT_NATURAL);
foreach (['conector', 'plugins', 'envato_versiones'] as $k) $h[$k] = (object)$h[$k];
file_put_contents($salida, json_encode($h, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
