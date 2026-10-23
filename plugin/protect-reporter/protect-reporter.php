<?php
/**
 * Plugin Name:       Protect Reporter
 * Description:       Sends a signed, read-only inventory report (software versions and file-check results) to TransFunnel Protect. Output only: it accepts no commands.
 * Version:           0.1.0
 * Requires at least: 5.9
 * Requires PHP:      7.4
 * Author:            TransFunnel
 * License:           Proprietary
 *
 * Rules this plugin must keep (see AGENTS.md in the Protect repo):
 * - It registers no REST route, AJAX handler or anything else that accepts outside input.
 *   The only inputs are its own admin-only, nonce-checked settings form and "Report now".
 * - It reads only the HTTP status of the platform's replies, never the body.
 * - It runs no shell commands and sends only the fixed data list in Protect_Reporter_Inventory.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'PROTECT_REPORTER_VERSION', '0.1.0' );
define( 'PROTECT_REPORTER_DIR', __DIR__ );
define( 'PROTECT_REPORTER_CRON_HOOK', 'protect_reporter_send' );

require_once PROTECT_REPORTER_DIR . '/includes/class-protect-reporter-inventory.php';
require_once PROTECT_REPORTER_DIR . '/includes/class-protect-reporter-checks.php';
require_once PROTECT_REPORTER_DIR . '/includes/class-protect-reporter-signer.php';
require_once PROTECT_REPORTER_DIR . '/includes/class-protect-reporter-sender.php';
require_once PROTECT_REPORTER_DIR . '/includes/class-protect-reporter-scheduler.php';

Protect_Reporter_Scheduler::register();

if ( is_admin() ) {
	require_once PROTECT_REPORTER_DIR . '/admin/class-protect-reporter-admin.php';
	Protect_Reporter_Admin::register();
}

register_activation_hook( __FILE__, array( 'Protect_Reporter_Scheduler', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Protect_Reporter_Scheduler', 'deactivate' ) );
