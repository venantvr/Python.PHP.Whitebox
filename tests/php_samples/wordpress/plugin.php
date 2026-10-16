<?php
/**
 * Plugin Name: Vulnerable Sample Plugin
 * Sample WordPress plugin exercising $wpdb, esc_*, sanitize_*, hooks and closures.
 */

if (!defined('ABSPATH')) {
    exit;
}

// VULN: SQL injection via $wpdb->get_results with concatenated input (hook callback closure)
add_action('wp_ajax_vsp_search', function () {
    global $wpdb;
    $term = $_POST['term'];
    $rows = $wpdb->get_results("SELECT * FROM {$wpdb->posts} WHERE post_title LIKE '%" . $term . "%'");
    wp_send_json($rows);
});

// SAFE: $wpdb->prepare with placeholders
add_action('wp_ajax_vsp_search_safe', function () {
    global $wpdb;
    $term = $_POST['term'];
    $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE post_title LIKE %s", '%' . $wpdb->esc_like($term) . '%'));
    wp_send_json($rows);
});

// VULN: tainted format string passed to prepare
function vsp_prepare_format() {
    global $wpdb;
    $orderby = $_GET['orderby'];
    return $wpdb->get_var($wpdb->prepare("SELECT ID FROM {$wpdb->posts} ORDER BY " . $orderby . " LIMIT %d", 1));
}

// SAFE: array_map('intval') whitelist of ids
function vsp_ids_safe() {
    global $wpdb;
    $ids = array_map('intval', (array) $_POST['ids']);
    return $wpdb->get_col("SELECT ID FROM {$wpdb->posts} WHERE ID IN (" . implode(',', $ids) . ")");
}

// VULN: XSS through _e() and echo of unescaped request var; SAFE: esc_html / esc_attr
function vsp_render_widget() {
    $name = isset($_GET['name']) ? wp_unslash($_GET['name']) : '';
    echo '<h2>' . $name . '</h2>';                      // VULN xss
    echo '<h2>' . esc_html($name) . '</h2>';            // SAFE
    echo '<input value="' . esc_attr($name) . '">';     // SAFE
    _e($name);                                           // VULN xss
    $clean = sanitize_text_field($_POST['bio']);
    echo '<p>' . $clean . '</p>';                       // SAFE (sanitize_text_field)
}

// VULN: open redirect via wp_redirect; SAFE: wp_safe_redirect
function vsp_redirect() {
    $to = $_GET['redirect_to'];
    if (isset($_GET['safe'])) {
        wp_safe_redirect($to);
        exit;
    }
    wp_redirect($to);
    exit;
}

// VULN: SSRF via wp_remote_get; SAFE: wp_safe_remote_get
function vsp_fetch() {
    $url = $_POST['feed_url'];
    $r1 = wp_remote_get($url);
    $r2 = wp_safe_remote_get($url);
    return array($r1, $r2);
}

// VULN: insecure deserialization via maybe_unserialize of a cookie
function vsp_cookie() {
    return maybe_unserialize($_COOKIE['vsp_prefs']);
}

// VULN: file inclusion via get_template_part with request var; SAFE: sanitize_key + whitelist
function vsp_template() {
    get_template_part('parts/' . $_GET['part']);
    $part = sanitize_key($_GET['part']);
    get_template_part('parts/' . $part);
}

// Privileged context: finding should be tagged (admin-only) and downgraded
function vsp_admin_tool() {
    if (!current_user_can('manage_options')) {
        wp_die('Forbidden');
    }
    $cmd = $_POST['cmd'];
    system('ls ' . $cmd);   // VULN rce (privileged-context)
}

// VULN: callback name from request passed to add_action -> code injection
function vsp_dynamic_hook() {
    add_action('init', $_GET['callback']);
    $fn = $_POST['fn'];
    $fn();
}

// VULN: nonce check is not sanitization; absint IS
function vsp_delete() {
    check_ajax_referer('vsp_nonce');
    global $wpdb;
    $id = $_POST['id'];
    $wpdb->query("DELETE FROM {$wpdb->posts} WHERE ID = " . $id);   // VULN sql (privileged-context)
    $safe_id = absint($_POST['id']);
    $wpdb->query("DELETE FROM {$wpdb->posts} WHERE ID = " . $safe_id); // SAFE
}

// VULN: email header injection through wp_mail headers
function vsp_contact() {
    $headers = 'From: ' . $_POST['email'];
    wp_mail(get_option('admin_email'), 'Contact', 'hello', $headers);
}
