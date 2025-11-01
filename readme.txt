=== Xero WooCommerce Invoicing Connector ===
Contributors: wemakethings
Donate link: https://paypal.me/wemakethingsuk
Tags: woocommerce, xero, invoicing, accounting, orders, sync
Requires at least: 6.0
Tested up to: 6.6
WC requires at least: 6.0
WC tested up to: 8.8
Stable tag: 1.0.0
License: GPL-2.0+
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Automatically creates and registers paid invoices in Xero upon WooCommerce order completion.

== Description ==

The **Xero WooCommerce Invoicing Connector** seamlessly integrates your e-commerce platform with your Xero accounting software, eliminating manual data entry and ensuring your financials are always up-to-date.

This plugin automatically handles the creation of invoices in Xero as soon as a customer completes a payment and their WooCommerce order is marked as *completed*. It handles various payment methods, and accurately maps customer and product data to your Xero contacts and items.

**Key Features:**

* **Automated Invoice Creation:** Generates a corresponding invoice in Xero instantly when a WooCommerce order is paid and completed.
* **Accurate Data Mapping:** Correctly maps customer details, product line items, discounts, and shipping charges.
* **Tax Compliance:** Ensures all applicable sales tax/VAT rules are correctly transferred to the Xero invoice.
* **Payment Handling:** Registers the payment against the invoice in Xero, marking it as paid (based on your configuration).
* **Error Logging:** Includes robust logging to help diagnose and resolve any synchronization issues.

== Installation ==

### 1. Standard Installation

1.  Upload the entire `xero-woocommerce-invoicing-connector` folder to the `/wp-content/plugins/` directory.
2.  Activate the plugin through the 'Plugins' menu in WordPress.

### 2. Configuration (Essential)

1.  Navigate to the new **Xero Connector** settings page under the WooCommerce menu.
2.  Follow the on-screen prompts to connect your Xero account using OAuth 2.0.
3.  Configure the essential settings, including:
    * The default **Sales Account** and **Tracking Categories** in Xero.
    * The WooCommerce order statuses that trigger the invoice creation (e.g., 'Completed').
    * Tax rate mapping between WooCommerce and Xero.
4.  Save your settings. The connector is now active and will sync new orders automatically.

== Frequently Asked Questions ==

= Does this plugin support refunds or cancelled orders? =
Version 1.0.0 focuses on the initial invoice creation for completed orders. Support for automated credit notes (for refunds) and cancelling pending invoices is planned for a future update.

= Where do I find the logs if a sync fails? =
The plugin logs all successful and failed synchronization attempts. You can find these under the **WooCommerce > Status > Logs** area, filtered by 'Xero Connector'.

= Can I choose which organisation in Xero to connect to? =
Yes, during the initial OAuth setup, you will be prompted to select the specific Xero organisation you wish to connect and sync data with.

== Screenshots ==

1. The initial connection and authorization screen for Xero.
2. The main settings page for mapping product/item details and tax accounts.
3. A view of the successful sync log, showing the Xero Invoice ID.

== Changelog ==

= 1.0.0 =
* Initial public release.
* Core functionality for automatic invoice creation upon order completion.
* OAuth 2.0 support for secure Xero connection.
* Customer, product line item, and tax data mapping.

== Upgrade Notice ==

= 1.0.0 =
This is the first stable release. No upgrade notice is required.