<?php
/**
 * Word Hunt - Must Use Core Loader
 *
 * @package     WordHunt
 * @author      Word Hunt Systems
 * @copyright   2026 Word Hunt Systems
 * @license     Proprietary - All Rights Reserved
 *
 * @wordpress-plugin
 * Plugin Name: Word Hunt - Must Use Core Loader
 * Description: Word Hunt platform autoloader and shared core utilities. Loads before all other plugins.
 * Version:     1.0.0
 * Text Domain: word-hunt
 * License:     Proprietary - All Rights Reserved
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Loads the Composer-generated PSR-4 autoloader.
 *
 * Registers the WordHunt\ namespace root so all platform plugins
 * can resolve classes without managing their own autoloaders.
 */
require_once __DIR__ . '/vendor/autoload.php';

/**
 * Word Hunt platform version.
 *
 * @var string
 */
define('WH_VERSION', '1.0.1');

/**
 * Absolute path to the wh-core plugin directory, with trailing slash.
 *
 * @var string
 */
define('WH_PATH', plugin_dir_path(__FILE__));

add_action('init', 'word_hunt_vault_bouncer');

/**
 * Redirects unauthorised requests away from vault-0.
 *
 * vault-0 is a headless internal WordPress instance with no public-facing
 * pages. Real access control is handled at the network layer by Cloudflare
 * IP allowlist rules. This function is a secondary courtesy redirect only.
 *
 * Access model:
 *   1. API requests (wp-json, graphql) are always allowed through.
 *      Required for Python workers, Vercel frontend, and WPGraphQL.
 *   2. All other restricted-area requests from users who are not logged
 *      in are silently redirected to word-hunt.com.
 *
 * No cookie mechanism or secret key is used. Cloudflare is the
 * authoritative security boundary for this host.
 *
 * @return void
 */
function word_hunt_vault_bouncer(): void
{
    /** @var string $request_uri Current request URI. */
    $request_uri = $_SERVER['REQUEST_URI'];

    /**
     * STEP 1: ALLOW API ACCESS
     *
     * Permit wp-json and graphql requests unconditionally.
     *
     * @var bool $is_api_call
     */
    $is_api_call = (
        strpos($request_uri, 'wp-json') !== false ||
        strpos($request_uri, 'graphql') !== false
    );

    if ($is_api_call) {
        return;
    }

    /**
     * STEP 2: BOUNCER LOGIC
     *
     * Restricted areas include the homepage, wp-login.php, and wp-admin.
     * Unauthenticated requests to these paths are redirected to word-hunt.com.
     *
     * @var bool $is_restricted_area
     */
    $is_restricted_area = (
        $request_uri === '/' ||
        strpos($request_uri, 'wp-login.php') !== false ||
        strpos($request_uri, 'wp-admin') !== false
    );

    if ($is_restricted_area && !is_user_logged_in()) {
        wp_redirect('https://word-hunt.com', 302);
        exit;
    }
}
