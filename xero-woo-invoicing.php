<?php
/**
 * Plugin Name: Xero WooCommerce Invoicing Connector
 * Description: Automatically creates and registers paid invoices in Xero upon WooCommerce order completion.
 * Version: 1.0.0
 * Author: Your Name
 * Requires at least: 5.0
 * Tested up to: 6.6
 * WC requires at least: 4.0
 * WC tested up to: 8.8
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Main class to orchestrate the plugin loading.
 */
class Xero_Woo_Invoicing_Connector {

    /**
     * Constructor: Load dependencies and initialize services.
     */
    public function __construct() {
        $this->load_dependencies();
        $this->initialize_services();
    }

    /**
     * Include all necessary files.
     */
    private function load_dependencies() {
        require_once plugin_dir_path( __FILE__ ) . 'includes/class-xero-api-manager.php';
        require_once plugin_dir_path( __FILE__ ) . 'includes/class-xero-woo-admin.php';
        require_once plugin_dir_path( __FILE__ ) . 'includes/class-xero-woo-sync.php';
    }

    /**
     * Instantiate the core classes.
     */
    private function initialize_services() {
        // The API Manager will now pull Client ID from options and determine the Redirect URI dynamically.
        $api_manager = new Xero_API_Manager();

        // Initialize Admin UI and OAuth flow handling
        new Xero_Woo_Admin( $api_manager );

        // Initialize the WooCommerce sync handler
        new Xero_Woo_Sync( $api_manager );
    }

    /**
     * Declares compatibility with High-Performance Order Storage (HPOS).
     * This method is hooked to 'before_woocommerce_init'.
     */
    public static function declare_hpos_compatibility() {
        if ( class_exists( '\Automattic\WooCommerce\Utilities\FeaturesUtil' ) ) {
            // Declares compatibility for the 'custom_order_tables' feature.
            \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'custom_order_tables', __FILE__, true );
        }
    }
}

// --- HPOS COMPATIBILITY DECLARATION ---
// This hook ensures compatibility is declared before WooCommerce fully initializes.
add_action( 'before_woocommerce_init', array( 'Xero_Woo_Invoicing_Connector', 'declare_hpos_compatibility' ) );

/**
 * Initialize the plugin after all dependencies are loaded.
 */
add_action( 'plugins_loaded', function() {
    // Ensure WooCommerce is active before trying to instantiate the class
    if ( class_exists( 'WooCommerce' ) ) {
        new Xero_Woo_Invoicing_Connector();
    } else {
        // Optional: display admin notice if WooCommerce is not active
    }
} );
