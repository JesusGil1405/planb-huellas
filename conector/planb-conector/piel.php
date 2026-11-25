<?php
if (!defined('ABSPATH')) exit;
// Se carga solo después de las clases de actualización de WordPress.
class Planb_Piel_Silenciosa extends WP_Upgrader_Skin
{
    public $msgs = array();
    public function feedback($f, ...$args) { if (is_string($f)) $this->msgs[] = $f; }
    public function header() {}
    public function footer() {}
    public function error($e) { $this->msgs[] = is_wp_error($e) ? $e->get_error_message() : (string)$e; }
}
