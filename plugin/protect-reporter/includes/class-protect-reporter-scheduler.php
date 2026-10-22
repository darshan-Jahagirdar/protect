<?php
/**
 * When reports are sent: hourly, right after any core/plugin/theme update, and when the
 * PHP version has changed since the last report (DESIGN.md §4.1).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Protect_Reporter_Scheduler {

	public static function register() {
		add_action( PROTECT_REPORTER_CRON_HOOK, array( 'Protect_Reporter_Sender', 'send_report' ) );
		add_action( PROTECT_REPORTER_CRON_HOOK . '_once', array( 'Protect_Reporter_Sender', 'send_report' ) );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'soon' ) );
		add_action( 'admin_init', array( __CLASS__, 'check_php_changed' ) );
	}

	public static function activate() {
		if ( ! wp_next_scheduled( PROTECT_REPORTER_CRON_HOOK ) ) {
			wp_schedule_event( time() + 60, 'hourly', PROTECT_REPORTER_CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( PROTECT_REPORTER_CRON_HOOK );
	}

	/** Queue a one-off report for the next cron run. */
	public static function soon() {
		if ( ! wp_next_scheduled( PROTECT_REPORTER_CRON_HOOK . '_once' ) ) {
			wp_schedule_single_event( time() + 10, PROTECT_REPORTER_CRON_HOOK . '_once' );
		}
	}

	public static function check_php_changed() {
		$last = get_option( 'protect_reporter_last_php' );
		if ( is_string( $last ) && PHP_VERSION !== $last ) {
			self::soon();
		}
	}
}
