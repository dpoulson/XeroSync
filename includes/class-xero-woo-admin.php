<?php
/**
 * Xero WooCommerce Admin Class
 * Manages the plugin's administration page, settings, and OAuth initiation.
 */
class Xero_Woo_Admin {

    private $api_manager;
    const PAGE_SLUG = 'xero-woo-invoicing';

    public function __construct( Xero_API_Manager $api_manager ) {
        $this->api_manager = $api_manager;

        add_action( 'admin_menu', [ $this, 'add_plugin_menu' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'admin_init', [ $this, 'handle_oauth_callback' ] );
        add_action( 'admin_notices', [ $this, 'display_connection_notices' ] );
        add_action( 'wp_ajax_xero_disconnect', [ $this, 'handle_disconnect' ] );
    }

    /**
     * Generates the dynamic redirect URI for the Xero App setup.
     */
    private function get_redirect_uri() {
        return admin_url( 'admin.php?page=' . self::PAGE_SLUG );
    }

    /**
     * Adds the plugin settings page to the WooCommerce menu.
     */
    public function add_plugin_menu() {
        add_submenu_page(
            'woocommerce',
            'Xero Invoicing Settings',
            'Xero Invoicing',
            'manage_options',
            self::PAGE_SLUG,
            [ $this, 'plugin_settings_page' ]
        );
    }

    /**
     * Registers all plugin settings for saving.
     */
    public function register_settings() {
        // Core Settings (Client ID, etc.)
        register_setting( 'xero_woo_settings_group', 'xero_client_id' );
        register_setting( 'xero_woo_settings_group', 'xero_default_sales_account' );
        register_setting( 'xero_woo_settings_group', 'xero_payment_mappings' );
    }

    /**
     * Handles the redirect from Xero after authorization.
     */
    public function handle_oauth_callback() {
        if ( isset( $_GET['page'] ) && $_GET['page'] === self::PAGE_SLUG && isset( $_GET['code'] ) ) {
            $code = sanitize_text_field( $_GET['code'] );
            $redirect_uri = $this->get_redirect_uri();

            if ( $this->api_manager->handle_oauth_redirect( $code, $redirect_uri ) ) {
                // Clear state/code verifier after successful exchange
                delete_option( Xero_API_Manager::VERIFIER_OPTION_KEY );
                wp_redirect( $redirect_uri . '&xero_connected=1' );
                exit;
            } else {
                wp_redirect( $redirect_uri . '&xero_connected=0' );
                exit;
            }
        }
    }

    /**
     * Handles the AJAX disconnect request.
     */
    public function handle_disconnect() {
        if ( ! current_user_can( 'manage_options' ) || ! check_ajax_referer( 'xero_disconnect_nonce', 'security' ) ) {
            wp_send_json_error( 'Permission denied.' );
        }

        delete_option( Xero_API_Manager::TOKEN_OPTION_KEY );
        delete_option( 'xero_tenant_id' );
        delete_option( Xero_API_Manager::VERIFIER_OPTION_KEY );
        delete_option( Xero_API_Manager::CLIENT_ID_KEY );

        wp_send_json_success( 'Disconnected from Xero.' );
    }

    /**
     * Displays connection status notices.
     */
    public function display_connection_notices() {
        if ( isset( $_GET['xero_connected'] ) && current_user_can( 'manage_options' ) ) {
            if ( $_GET['xero_connected'] === '1' ) {
                echo '<div class="notice notice-success is-dismissible"><p>Successfully connected to Xero!</p></div>';
            } elseif ( $_GET['xero_connected'] === '0' ) {
                echo '<div class="notice notice-error is-dismissible"><p>Failed to connect to Xero. Check your Client ID and Redirect URI setup.</p></div>';
            }
        }
    }

    /**
     * Renders the main settings page content.
     */
    public function plugin_settings_page() {
        ?>
        <div class="wrap">
            <h1>Xero WooCommerce Invoicing Connector</h1>
            <form method="post" action="options.php">
                <?php settings_fields( 'xero_woo_settings_group' ); ?>
                <?php do_settings_sections( 'xero_woo_settings_group' ); ?>

                <h2>1. Xero API Connection</h2>
                <?php $this->render_oauth_connection_status(); ?>

                <h2>2. Default Accounting Settings</h2>
                <?php $this->render_default_accounts_section(); ?>

                <h2>3. Payment Method Mapping</h2>
                <?php $this->render_payment_mapping_section(); ?>

                <?php submit_button(); ?>
            </form>
        </div>
        <?php
        $this->render_admin_scripts();
    }

    /**
     * Renders the Client ID input and OAuth connection button/status.
     */
    private function render_oauth_connection_status() {
        $access_token = $this->api_manager->get_valid_access_token();
        $redirect_uri = $this->get_redirect_uri();
        $client_id = get_option( Xero_API_Manager::CLIENT_ID_KEY );
        $tenant_id = get_option( 'xero_tenant_id' );
        $tenant_status = $tenant_id ? 'Connected' : 'Tenant ID not found. Try reconnecting.';

        echo '<table class="form-table">';

        // Client ID Input Field
        echo '<tr><th><label for="xero_client_id">Client ID (PKCE)</label></th><td>';
        printf(
            '<input type="text" id="xero_client_id" name="%s" value="%s" class="regular-text" placeholder="Enter your Xero Application Client ID" />',
            Xero_API_Manager::CLIENT_ID_KEY,
            esc_attr( $client_id )
        );
        echo '<p class="description">Your Client ID from the Xero Developer Portal. Since you are using PKCE, no secret is required.</p>';
        echo '</td></tr>';

        // Dynamic Redirect URI Display
        echo '<tr><th><label>Redirect URI</label></th><td>';
        printf(
            '<code style="background-color: #f3f3f3; padding: 5px 10px; border: 1px solid #ccc; display: inline-block;">%s</code>',
            esc_html( $redirect_uri )
        );
        echo '<p class="description">Copy this URL exactly into the "Redirect URI" field in your Xero App settings.</p>';
        echo '</td></tr>';

        // Connection Status and Button
        echo '<tr><th>Connection Status</th><td>';
        if ( $access_token ) {
            echo '<span style="color: green; font-weight: bold;">CONNECTED</span><br>';
            echo '<p>Tenant ID Status: ' . esc_html( $tenant_status ) . '</p>';
            echo '<button type="button" id="xero-disconnect-btn" class="button button-secondary">Disconnect Xero</button>';
        } else {
            if ( empty( $client_id ) ) {
                 echo '<span style="color: red; font-weight: bold;">DISCONNECTED</span> (Please save your Client ID first)';
            } else {
                $auth_url = $this->api_manager->generate_auth_url( $redirect_uri );
                echo '<a href="' . esc_url( $auth_url ) . '" class="button button-primary">Connect to Xero App</a>';
                echo '<p class="description">You must save your Client ID above before connecting.</p>';
            }
        }
        echo '</td></tr>';

        echo '</table>';
    }

    /**
     * Renders the section for default account code setup.
     */
    private function render_default_accounts_section() {
        $current_code = get_option( 'xero_default_sales_account', '' );

        // Fetch real sales accounts from Xero API
        $xero_sales_accounts = $this->api_manager->get_sales_accounts();
        $is_connected = ! empty( $xero_sales_accounts );

        echo '<table class="form-table"><tr><th><label for="xero_default_sales_account">Default Sales Account Code</label></th><td>';

        if ( ! $is_connected ) {
            // Show connection warning and a disabled select or text input
            echo '<div class="notice notice-warning inline"><p><strong>Warning:</strong> You must be connected to Xero to fetch Sales Account Codes. Please connect in Section 1.</p></div>';
            
            // Add a placeholder/empty option if disconnected to display the message
            $xero_sales_accounts = ['000' => 'Accounts not fetched (Disconnected)'];
        }

        // Render the select dropdown
        echo '<select id="xero_default_sales_account" name="xero_default_sales_account" class="regular-text" ' . ( $is_connected ? '' : 'disabled' ) . '>';
        echo '<option value="">-- Select Sales Account --</option>';

        // Populate dropdown with fetched Xero Sales Accounts
        foreach ( $xero_sales_accounts as $code => $name ) {
            printf(
                '<option value="%s" %s>%s</option>',
                esc_attr( $code ),
                selected( $current_code, $code, false ),
                esc_html( $name )
            );
        }
        echo '</select>';

        echo '<p class="description">The default Xero Account Code for product sales (Revenue). Accounts are dynamically pulled from your connected Xero organization.</p>';
        echo '</td></tr></table>';
    }

    /**
     * Renders the WooCommerce Payment Method to Xero Bank Account mapping table.
     */
    private function render_payment_mapping_section() {
        $payment_gateways = WC()->payment_gateways->payment_gateways();
        $mappings = get_option( 'xero_payment_mappings', [] );

        // Fetch real bank accounts from Xero API
        $xero_bank_accounts = $this->api_manager->get_bank_accounts();
        $is_connected = ! empty( $xero_bank_accounts );

        if ( empty( $payment_gateways ) ) {
            echo '<p>No active WooCommerce payment gateways found.</p>';
            return;
        }

        if ( ! $is_connected ) {
            echo '<div class="notice notice-warning inline"><p><strong>Warning:</strong> You must be connected to Xero to fetch and map Bank Accounts. Please connect in Section 1.</p></div>';
            // Fallback: If disconnected, show a disabled table but don't stop rendering
            $xero_bank_accounts = ['000' => 'Accounts not fetched (Disconnected)'];
        }

        echo '<table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr><th>WooCommerce Payment Method</th><th>Xero Bank Account Code</th></tr></thead>';
        echo '<tbody>';

        foreach ( $payment_gateways as $id => $gateway ) {
            if ( 'yes' === $gateway->enabled ) {
                $current_mapping = $mappings[ $id ] ?? '';
                echo '<tr>';
                echo '<td>' . esc_html( $gateway->get_method_title() ) . ' (' . esc_html( $id ) . ')</td>';
                echo '<td>';
                echo '<select name="xero_payment_mappings[' . esc_attr( $id ) . ']" ' . ( $is_connected ? '' : 'disabled' ) . '>';
                echo '<option value="">-- Select Xero Account --</option>';

                // Populate dropdown with fetched Xero Bank Accounts
                foreach ( $xero_bank_accounts as $code => $name ) {
                    printf(
                        '<option value="%s" %s>%s</option>',
                        esc_attr( $code ),
                        selected( $current_mapping, $code, false ),
                        esc_html( $name )
                    );
                }
                echo '</select>';
                echo '</td>';
                echo '</tr>';
            }
        }

        echo '</tbody></table>';
        if ( $is_connected ) {
             echo '<p class="description">Map each active WooCommerce payment method to the corresponding Xero Bank Account code where the funds are deposited. Accounts are dynamically pulled from your connected Xero organization.</p>';
        } else {
             echo '<p class="description">Once connected to Xero, the available bank accounts will appear in the dropdown menus above.</p>';
        }
    }

    /**
     * Renders inline scripts for AJAX disconnect.
     */
    private function render_admin_scripts() {
        ?>
        <script>
            jQuery(document).ready(function($) {
                $('#xero-disconnect-btn').on('click', function(e) {
                    e.preventDefault();
                    if (confirm('Are you sure you want to disconnect from Xero? This will remove all stored tokens.')) {
                        var $button = $(this);
                        $button.prop('disabled', true).text('Disconnecting...');

                        $.ajax({
                            url: ajaxurl,
                            type: 'POST',
                            data: {
                                action: 'xero_disconnect',
                                security: '<?php echo wp_create_nonce( 'xero_disconnect_nonce' ); ?>'
                            },
                            success: function(response) {
                                if (response.success) {
                                    alert('Successfully disconnected. Refreshing page...');
                                    window.location.reload();
                                } else {
                                    alert('Disconnect failed: ' + (response.data || 'Unknown error'));
                                    $button.prop('disabled', false).text('Disconnect Xero');
                                }
                            },
                            error: function() {
                                alert('An error occurred during AJAX call.');
                                $button.prop('disabled', false).text('Disconnect Xero');
                            }
                        });
                    }
                });
            });
        </script>
        <?php
    }
}
