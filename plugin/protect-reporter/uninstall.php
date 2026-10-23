<?php
/**
 * Removes everything the plugin stored. It doesn't contact the platform: removing a site
 * there is done by the Protect team.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

foreach ( array( 'protect_reporter_keypair', 'protect_reporter_settings', 'protect_reporter_last', 'protect_reporter_last_php', 'protect_reporter_scan', 'protect_reporter_checks' ) as $option ) {
	delete_option( $option );
}
wp_clear_scheduled_hook( 'protect_reporter_send' );
wp_clear_scheduled_hook( 'protect_reporter_send_once' );

// Cached official checksums.
global $wpdb;
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_protect\\_reporter\\_%' OR option_name LIKE '\\_transient\\_timeout\\_protect\\_reporter\\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
