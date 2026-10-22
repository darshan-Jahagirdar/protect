<?php
/**
 * Removes everything the plugin stored. It doesn't contact the platform: removing a site
 * there is done by the Protect team.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

foreach ( array( 'protect_reporter_keypair', 'protect_reporter_settings', 'protect_reporter_last', 'protect_reporter_last_php' ) as $option ) {
	delete_option( $option );
}
wp_clear_scheduled_hook( 'protect_reporter_send' );
wp_clear_scheduled_hook( 'protect_reporter_send_once' );
