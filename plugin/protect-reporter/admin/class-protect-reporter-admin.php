<?php
/**
 * Settings > Protect Reporter: connect to the platform, "Report now", and the
 * transparency view of exactly what was last sent.
 *
 * Both form actions go through admin-post.php, need the manage_options capability and a
 * valid nonce. They are the plugin's only inputs, and only a site administrator can use them.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Protect_Reporter_Admin {

	const PAGE = 'protect-reporter';

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_post_protect_reporter_enroll', array( __CLASS__, 'handle_enroll' ) );
		add_action( 'admin_post_protect_reporter_report_now', array( __CLASS__, 'handle_report_now' ) );
	}

	public static function menu() {
		add_options_page( 'Protect Reporter', 'Protect Reporter', 'manage_options', self::PAGE, array( __CLASS__, 'render' ) );
	}

	private static function page_url( $args = array() ) {
		return add_query_arg( array_merge( array( 'page' => self::PAGE ), $args ), admin_url( 'options-general.php' ) );
	}

	private static function guard( $action ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.' ), 403 );
		}
		check_admin_referer( $action );
	}

	public static function handle_enroll() {
		self::guard( 'protect_reporter_enroll' );
		$url  = isset( $_POST['platform_url'] ) ? esc_url_raw( wp_unslash( $_POST['platform_url'] ), array( 'http', 'https' ) ) : '';
		$code = isset( $_POST['enrollment_code'] ) ? sanitize_text_field( wp_unslash( $_POST['enrollment_code'] ) ) : '';

		if ( ! Protect_Reporter_Sender::valid_platform_url( $url ) ) {
			$result = 'bad_url';
		} else {
			$status = Protect_Reporter_Sender::enroll( $url, $code );
			$result = 204 === $status ? 'enrolled' : 'enroll_failed_' . (int) $status;
			if ( 204 === $status ) {
				Protect_Reporter_Sender::send_report(); // first report straight away
			}
		}
		wp_safe_redirect( self::page_url( array( 'protect_result' => $result ) ) );
		exit;
	}

	public static function handle_report_now() {
		self::guard( 'protect_reporter_report_now' );
		$status = Protect_Reporter_Sender::send_report();
		wp_safe_redirect( self::page_url( array( 'protect_result' => 'report_' . (int) $status ) ) );
		exit;
	}

	private static function notice() {
		// Display-only flag set by our own redirects above; never acted on.
		$result = isset( $_GET['protect_result'] ) ? sanitize_key( wp_unslash( $_GET['protect_result'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' === $result ) {
			return;
		}
		$messages = array(
			'enrolled'   => array( 'success', 'Connected to Protect. The first report has been sent.' ),
			'bad_url'    => array( 'error', 'The platform URL must use https:// (plain http only on local or development sites).' ),
			'report_204' => array( 'success', 'Report sent and accepted.' ),
			'report_0'   => array( 'error', 'No report was sent. Check that this site is connected and that PHP isn\'t running from the command line.' ),
		);
		if ( isset( $messages[ $result ] ) ) {
			list( $type, $text ) = $messages[ $result ];
		} elseif ( 0 === strpos( $result, 'enroll_failed_' ) ) {
			$type = 'error';
			$text = 'Connecting failed (HTTP ' . substr( $result, 14 ) . '). Check the code (they expire after 24 hours and work once) and the platform URL.';
		} else {
			$type = 'error';
			$text = 'The report was refused (HTTP ' . substr( $result, 7 ) . ').';
		}
		printf( '<div class="notice notice-%1$s"><p>%2$s</p></div>', esc_attr( $type ), esc_html( $text ) );
	}

	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$settings = Protect_Reporter_Sender::settings();
		$last     = get_option( Protect_Reporter_Sender::LAST );
		$next     = wp_next_scheduled( PROTECT_REPORTER_CRON_HOOK );
		?>
		<div class="wrap">
			<h1>Protect Reporter</h1>
			<?php self::notice(); ?>
			<p>This plugin sends TransFunnel Protect a signed list of this site's software versions and file-check results. It sends only; it cannot receive commands or change this site. It never sends visitor data, logs, database contents, file contents or passwords.</p>

			<h2>Status</h2>
			<table class="form-table" role="presentation">
				<tr><th scope="row">Connected</th><td><?php echo empty( $settings['key_id'] ) ? 'No' : 'Yes, since ' . esc_html( $settings['enrolled_at'] ); ?></td></tr>
				<tr><th scope="row">Platform</th><td><?php echo esc_html( isset( $settings['platform_url'] ) ? $settings['platform_url'] : '—' ); ?></td></tr>
				<tr><th scope="row">Key ID</th><td><code><?php echo esc_html( isset( $settings['key_id'] ) ? $settings['key_id'] : '—' ); ?></code></td></tr>
				<tr><th scope="row">Last report</th><td><?php echo is_array( $last ) ? esc_html( $last['at'] . ' (HTTP ' . $last['status'] . ')' ) : 'None yet'; ?></td></tr>
				<tr><th scope="row">Next scheduled</th><td><?php echo $next ? esc_html( gmdate( 'Y-m-d H:i:s', $next ) . ' UTC' ) : 'Not scheduled'; ?></td></tr>
			</table>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="protect_reporter_report_now">
				<?php wp_nonce_field( 'protect_reporter_report_now' ); ?>
				<?php submit_button( 'Report now', 'primary', 'submit', false, empty( $settings['key_id'] ) ? array( 'disabled' => 'disabled' ) : array() ); ?>
			</form>

			<h2><?php echo empty( $settings['key_id'] ) ? 'Connect' : 'Reconnect (new key)'; ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="protect_reporter_enroll">
				<?php wp_nonce_field( 'protect_reporter_enroll' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="platform_url">Platform URL</label></th>
						<td><input name="platform_url" id="platform_url" type="url" class="regular-text" required value="<?php echo esc_attr( isset( $settings['platform_url'] ) ? $settings['platform_url'] : '' ); ?>"></td>
					</tr>
					<tr>
						<th scope="row"><label for="enrollment_code">Enrollment code</label></th>
						<td><input name="enrollment_code" id="enrollment_code" type="text" class="regular-text" required autocomplete="off" placeholder="XXXX-XXXX-XXXX-XXXX">
						<p class="description">One-time code from the Protect team. Valid for 24 hours.</p></td>
					</tr>
				</table>
				<?php submit_button( empty( $settings['key_id'] ) ? 'Connect' : 'Reconnect', 'secondary' ); ?>
			</form>

			<h2>Exactly what was last sent</h2>
			<?php if ( is_array( $last ) && ! empty( $last['payload'] ) ) : ?>
				<pre style="max-height:480px;overflow:auto;background:#fff;border:1px solid #c3c4c7;padding:12px;"><?php echo esc_html( wp_json_encode( json_decode( $last['payload'] ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) ); ?></pre>
			<?php else : ?>
				<p>Nothing has been sent yet.</p>
			<?php endif; ?>
		</div>
		<?php
	}
}
