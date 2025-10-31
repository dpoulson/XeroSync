<?php
/**
 * Xero WooCommerce Synchronization Class
 * Handles linking WooCommerce events (like order status changes) to Xero API calls.
 */
class Xero_Woo_Sync {

    private $api_manager;

    public function __construct( Xero_API_Manager $api_manager ) {
        $this->api_manager = $api_manager;

        // Hook into the WooCommerce action fired when an order status changes to 'completed'
        add_action( 'woocommerce_order_status_completed', [ $this, 'process_order_for_xero' ] );
    }

    /**
     * Processes a completed WooCommerce order and attempts to sync it to Xero.
     *
     * @param int $order_id The ID of the WooCommerce order.
     */
    public function process_order_for_xero( $order_id ) {
        // Prevent recursive calls and ensure execution only happens once
        if ( get_post_meta( $order_id, '_xero_synced', true ) === 'yes' ) {
            return;
        }

        $order = wc_get_order( $order_id );

        // Basic check for valid order and total
        if ( ! $order || $order->get_total() <= 0 ) {
            return;
        }

        // Check if the order has already been paid for (which it should be if status is 'completed')
        if ( ! $order->is_paid() ) {
            $order->add_order_note( 'Xero Sync Skipped: Order status is completed but WooCommerce does not consider it paid.' );
            return;
        }

        $order->add_order_note( 'Attempting to synchronize order with Xero.' );

        // Call the master synchronization method in the API Manager
        $success = $this->api_manager->sync_order_to_xero( $order );

        if ( $success ) {
            // Mark the order as synced to prevent duplicate invoices on re-saves
            update_post_meta( $order_id, '_xero_synced', 'yes' );
        } else {
            // Log a failure note if the sync method returns false
            $order->add_order_note( 'Xero Synchronization failed. See debug log for details.' );
        }
    }
}
