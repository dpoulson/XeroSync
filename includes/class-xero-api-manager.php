<?php
/**
 * Xero API Manager Class
 * Handles OAuth 2.0 PKCE flow, token management, and all Xero API requests.
 */
class Xero_API_Manager {

    const TOKEN_OPTION_KEY = 'xero_oauth_tokens';
    const VERIFIER_OPTION_KEY = 'xero_pkce_verifier';
    const CLIENT_ID_KEY = 'xero_client_id';
    
    // Encryption constants and properties
    private $encryption_key;
    const ENCRYPTION_CIPHER = 'aes-256-cbc';

    public function __construct() {
        
        $raw_key = '';
        
        // 1. Primary choice: Dedicated encryption key (Recommended)
        if ( defined( 'XERO_ENCRYPTION_KEY' ) ) {
            $raw_key = XERO_ENCRYPTION_KEY;
        } 
        // 2. Secondary choice: Fallback to a WordPress security salt
        else if ( defined( 'AUTH_KEY' ) ) {
            $raw_key = AUTH_KEY;
        } 
        // 3. Fallback: Hardcoded (Unsafe for Production)
        else {
            $raw_key = 'A_SECURE_32_BYTE_ENCRYPTION_KEY_1234'; 
            error_log('SECURITY ERROR: Xero API encryption key is hardcoded. Define XERO_ENCRYPTION_KEY or AUTH_KEY.');
        }
        
        // Generate a 32-byte (256-bit) key from the raw key material using SHA-256 hash.
        // This ensures the key is the correct length for aes-256-cbc.
        $this->encryption_key = substr( hash( 'sha256', $raw_key, true ), 0, 32 );
        
    }
    
    /**
     * Encrypts and serializes data for storage.
     * @param mixed $data The data (string or array) to encrypt.
     * @return string|false JSON encoded string containing encrypted data and IV, or false on failure.
     */
    private function encrypt_and_save( $data ) {
        $serialized_data = is_array( $data ) ? serialize( $data ) : (string) $data;
        $iv_length = openssl_cipher_iv_length( self::ENCRYPTION_CIPHER );
        $iv = openssl_random_pseudo_bytes( $iv_length );

        $encrypted = openssl_encrypt( $serialized_data, self::ENCRYPTION_CIPHER, $this->encryption_key, 0, $iv );

        if ( $encrypted === false ) {
            return false;
        }

        $json = json_encode([
            'data' => base64_encode( $encrypted ),
            'iv'   => base64_encode( $iv ),
        ]);

        return $json;
    }

    /**
     * Decrypts and unserializes data retrieved from storage.
     * @param string $json_data The JSON encoded string from encrypt_and_save.
     * @return mixed|false The decrypted and unserialized data (string or array) or false on failure.
     */
    private function retrieve_and_decrypt( $json_data ) {
        if ( empty( $json_data ) ) {
            return false;
        }

        $data = json_decode( $json_data, true );

        if ( ! $data || ! isset( $data['data'], $data['iv'] ) ) {
            // This handles cases where data might not be encrypted yet or is malformed
            return $json_data; 
        }

        $iv = base64_decode( $data['iv'] );
        $encrypted_data = base64_decode( $data['data'] );

        $decrypted_data = openssl_decrypt( $encrypted_data, self::ENCRYPTION_CIPHER, $this->encryption_key, 0, $iv );

        if ( $decrypted_data === false ) {
            return false;
        }

        // Attempt to unserialize the data.
        $unserialized = @unserialize( $decrypted_data );

        // Check for serialized 'false' (b:0;)
        if ( $unserialized !== false || $decrypted_data === 'b:0;' ) {
            return $unserialized;
        }

        return $decrypted_data; // Return as string if not serialized
    }

    /**
     * Generates PKCE code verifier and challenge.
     * @return array { 'verifier': string, 'challenge': string }
     */
    private function generate_pkce_codes() {
        $verifier = bin2hex( random_bytes( 32 ) ); // Generate a random 64-char string (32 bytes * 2)
        $challenge = rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );

        // Store the ENCRYPTED verifier for later use during code exchange
        update_option( self::VERIFIER_OPTION_KEY, $this->encrypt_and_save( $verifier ) );

        return [
            'verifier' => $verifier,
            'challenge' => $challenge,
        ];
    }

    /**
     * Generates the Xero authorization URL using PKCE.
     * @param string $redirect_uri The dynamically generated redirect URI.
     * @return string The full authorization URL.
     */
    public function generate_auth_url( $redirect_uri ) {
        $client_id = get_option( self::CLIENT_ID_KEY );
        if ( empty( $client_id ) ) {
            return false;
        }

        $codes = $this->generate_pkce_codes();

        $scope = 'openid profile email offline_access accounting.transactions accounting.settings';
        $state = uniqid( 'xero_state_', true );

        $params = [
            'response_type'        => 'code',
            'client_id'            => $client_id,
            'redirect_uri'         => $redirect_uri,
            'scope'                => $scope,
            'state'                => $state,
            'code_challenge'       => $codes['challenge'],
            'code_challenge_method'=> 'S256',
        ];

        return 'https://login.xero.com/identity/connect/authorize?' . http_build_query( $params );
    }

    /**
     * Handles the OAuth 2.0 redirect, exchanging the code for tokens.
     * @param string $code The authorization code from Xero.
     * @param string $redirect_uri The dynamically generated redirect URI.
     * @return bool True on success, false on failure.
     */
    public function handle_oauth_redirect( $code, $redirect_uri ) {
        $client_id = get_option( self::CLIENT_ID_KEY );
        // Retrieve and DECRYPT the verifier
        $code_verifier = $this->retrieve_and_decrypt( get_option( self::VERIFIER_OPTION_KEY ) );

        if ( empty( $client_id ) || empty( $code_verifier ) ) {
            error_log( 'Xero OAuth Error: Client ID or PKCE verifier missing/could not be decrypted.' );
            return false;
        }

        $token_url = 'https://identity.xero.com/connect/token';
        $response = wp_remote_post( $token_url, [
            'headers' => [ 'Content-Type' => 'application/x-www-form-urlencoded' ],
            'body'    => [
                'grant_type'         => 'authorization_code',
                'code'               => $code,
                'redirect_uri'       => $redirect_uri,
                'client_id'          => $client_id,
                'code_verifier'      => $code_verifier, // PKCE Verifier
            ],
        ]);

        if ( is_wp_error( $response ) ) {
            error_log( 'Xero OAuth Token Error: ' . $response->get_error_message() );
            return false;
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( isset( $data['access_token'] ) ) {
            $data['expires_at'] = time() + $data['expires_in'];
            // ENCRYPT and store the tokens array
            update_option( self::TOKEN_OPTION_KEY, $this->encrypt_and_save( $data ) );

            // Fetch tenant ID
            return $this->fetch_tenant_id( $data['access_token'] );
        }

        error_log( 'Xero OAuth Token Failure: ' . $body );
        return false;
    }

    /**
     * Fetches the Xero Tenant (Organisation) ID after successful token exchange.
     * @param string $access_token
     * @return bool True on success, false on failure.
     */
    private function fetch_tenant_id( $access_token ) {
        $connections_url = 'https://api.xero.com/connections';
        $response = wp_remote_get( $connections_url, [
            'headers' => [
                'Authorization' => 'Bearer ' . $access_token,
                'Content-Type'  => 'application/json',
            ],
        ]);

        if ( is_wp_error( $response ) ) {
            error_log( 'Xero Tenant ID Error: ' . $response->get_error_message() );
            return false;
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( ! empty( $data ) && is_array( $data ) ) {
            // We use the first tenant ID found.
            update_option( 'xero_tenant_id', $data[0]['tenantId'] );
            return true;
        }

        error_log( 'Xero Tenant ID Failure: Could not find tenant ID. Response: ' . $body );
        return false;
    }

    /**
     * Retrieves a valid access token, refreshing it if necessary.
     * @return string|false Valid access token or false on failure.
     */
    public function get_valid_access_token() {
        // Retrieve and DECRYPT the tokens array
        $tokens = $this->retrieve_and_decrypt( get_option( self::TOKEN_OPTION_KEY ) );
        $client_id = get_option( self::CLIENT_ID_KEY );

        if ( empty( $tokens ) || empty( $client_id ) ) {
            return false; // Not configured or not connected, or decryption failed
        }

        // Check if token is still valid
        if ( $tokens['expires_at'] > time() + 60 ) { // Check 60 seconds before actual expiry
            return $tokens['access_token'];
        }

        // Token expired or near expiry, attempt refresh
        if ( ! isset( $tokens['refresh_token'] ) ) {
            error_log( 'Xero Token Refresh Error: Refresh token missing.' );
            return false;
        }

        error_log( 'Refreshing Xero Token' );

        $token_url = 'https://identity.xero.com/connect/token';
        $response = wp_remote_post( $token_url, [
            'headers' => [ 'Content-Type' => 'application/x-www-form-urlencoded' ],
            'body'    => [
                'grant_type'    => 'refresh_token',
                'refresh_token' => $tokens['refresh_token'],
                'client_id'     => $client_id,
            ],
        ]);



        if ( is_wp_error( $response ) ) {
            error_log( 'Xero Token Refresh API Error: ' . $response->get_error_message() );
            return false;
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( isset( $data['access_token'] ) ) {
            $data['expires_at'] = time() + $data['expires_in'];
            // Merge updated data and ENCRYPT the entire array before saving
            $new_tokens = array_merge( $tokens, $data );
            update_option( self::TOKEN_OPTION_KEY, $this->encrypt_and_save( $new_tokens ) );
            return $data['access_token'];
        }

        error_log( 'Xero Token Refresh Failure: ' . $body );
        return false;
    }

    // --- Xero API Interaction Methods ---

    /**
     * Common request method for Xero API.
     */
    private function xero_api_request( $method, $endpoint, $access_token, $tenant_id, $data = [] ) {
        $url = "https://api.xero.com/api.xro/2.0/{$endpoint}";
        $args = [
            'method'  => $method,
            'headers' => [
                'Authorization' => 'Bearer ' . $access_token,
                'Xero-Tenant-Id' => $tenant_id,
                'Accept'        => 'application/json',
            ],
            'timeout' => 30,
        ];

        if ( in_array( $method, [ 'POST', 'PUT' ] ) ) {
            $args['headers']['Content-Type'] = 'application/json';
            $args['body'] = json_encode( $data );
        }

        $response = wp_remote_request( $url, $args );

        if ( is_wp_error( $response ) ) {
            error_log( "Xero API Error ($endpoint): " . $response->get_error_message() );
            return false;
        }

        $body = wp_remote_retrieve_body( $response );
        $http_code = wp_remote_retrieve_response_code( $response );

        if ( $http_code >= 400 ) {
            // Log the full body for detailed validation errors
            error_log( "Xero API HTTP Error ($endpoint - Code $http_code): " . $body );
            return false;
        }

        return json_decode( $body, true );
    }

    /**
     * Retrieves a list of Bank Account Codes from Xero for mapping.
     * @return array Array of bank accounts (Code => Name), or empty array on failure.
     */
    public function get_bank_accounts() {
        $access_token = $this->get_valid_access_token();
        $tenant_id = get_option( 'xero_tenant_id' );

        if ( ! $access_token || ! $tenant_id ) {
            return [];
        }

        // Use a filter to only retrieve bank accounts
        $endpoint = 'Accounts?where=Type=="BANK"';
        $response = $this->xero_api_request( 'GET', $endpoint, $access_token, $tenant_id );

        $accounts = [];

        if ( $response && isset( $response['Accounts'] ) ) {
            foreach ( $response['Accounts'] as $account ) {
                if ( ! empty( $account['Code'] ) && ! empty( $account['Name'] ) ) {
                    // Map the Code to a display Name (Name (Code))
                    $accounts[ $account['Code'] ] = $account['Name'] . ' (' . $account['Code'] . ')';
                }
            }
        }

        return $accounts;
    }

    /**
     * Retrieves a list of Sales Revenue Account Codes from Xero for mapping.
     * Filters for accounts of type REVENUE, OTHERINCOME, or SALES.
     * @return array Array of sales accounts (Code => Name), or empty array on failure.
     */
    public function get_sales_accounts() {
        $access_token = $this->get_valid_access_token();
        $tenant_id = get_option( 'xero_tenant_id' );

        if ( ! $access_token || ! $tenant_id ) {
            return [];
        }

        // Filter for revenue/sales accounts. Use a URL-encoded filter string.
        $filter = urlencode('Type=="REVENUE" OR Type=="OTHERINCOME"');
        $endpoint = "Accounts?where={$filter}";
        $response = $this->xero_api_request( 'GET', $endpoint, $access_token, $tenant_id );

        $accounts = [];

        if ( $response && isset( $response['Accounts'] ) ) {
            foreach ( $response['Accounts'] as $account ) {
                if ( ! empty( $account['Code'] ) && ! empty( $account['Name'] ) ) {
                    // Map the Code to a display Name (Name (Code))
                    $accounts[ $account['Code'] ] = $account['Name'] . ' (' . $account['Code'] . ')';
                }
            }
        }

        return $accounts;
    }

    /**
     * === CORE SYNCHRONIZATION METHOD ===
     * Orchestrates the entire order synchronization process to Xero.
     * @param WC_Order $order The WooCommerce order object.
     * @return bool True on success, false on failure.
     */
    public function sync_order_to_xero( $order ) {
        $access_token = $this->get_valid_access_token();
        $tenant_id = get_option( 'xero_tenant_id' );

        if ( ! $access_token || ! $tenant_id ) {
            $order->add_order_note( 'Xero Sync Failed: Plugin not connected or token expired.' );
            return false;
        }

        // 1. Get Contact Data (used by Xero for matching or creating the customer contact)
        $contact_data = $this->get_contact_details_for_xero( $order );
        if ( ! $contact_data ) {
            $order->add_order_note( 'Xero Sync Failed: Could not get contact details from order.' );
            return false;
        }

        // 2. Prepare Line Items (now includes item lookup/creation)
        $line_items = $this->prepare_invoice_line_items( $order, $access_token, $tenant_id );
        if ( empty( $line_items ) ) {
            $order->add_order_note( 'Xero Sync Failed: No valid line items found.' );
            return false;
        }

        // 3. Create and Register Paid Invoice
        $sync_success = $this->create_and_register_paid_invoice( $order, $contact_data, $line_items, $access_token, $tenant_id );

        if ( $sync_success ) {
            // Note is added inside create_and_register_paid_invoice now
            return true;
        } else {
            $order->add_order_note( 'Xero Sync Failed: Invoice creation failed. Check PHP error logs.' );
            return false;
        }
    }

    /**
     * Helper to format WooCommerce address fields into Xero Address structure.
     * @param WC_Order $order
     * @param string $type 'billing' or 'shipping'
     * @param string $xero_type 'STREET' or 'POBOX'
     * @return array Xero Address array (for the Addresses collection).
     */
    private function format_address_for_xero( $order, $type, $xero_type ) {
        // Use WC_Order methods to safely retrieve address fields.
        $address_1 = $order->{"get_{$type}_address_1"}();
        $address_2 = $order->{"get_{$type}_address_2"}();
        $city      = $order->{"get_{$type}_city"}();
        $state     = $order->{"get_{$type}_state"}();
        $postcode  = $order->{"get_{$type}_postcode"}();
        $country   = $order->{"get_{$type}_country"}();

        // Only include address if at least one primary field is present
        if ( empty( $address_1 ) && empty( $city ) ) {
            return [];
        }

        $address_lines = array_filter( [ $address_1, $address_2 ] );
        
        // Xero requires AddressLine1-4. WooCommerce generally uses 2 lines.
        // We will map the available lines.
        $xero_address = [
            'AddressType'   => $xero_type, 
            'AddressLine1'  => $address_lines[0] ?? null,
            'AddressLine2'  => $address_lines[1] ?? null,
            // Line 3 and 4 are often unused in standard WC checkout
            'City'          => $city,
            'Region'        => $state,
            'PostalCode'    => $postcode,
            'Country'       => $country,
        ];
        
        // Filter out null or empty values for clean API payload
        return array_filter( $xero_address ); 
    }

    /**
     * Extracts contact details (including addresses) from the WC_Order for Xero Contact matching/creation.
     * @param WC_Order $order
     * @return array|false Xero Contact detail array or false.
     */
    private function get_contact_details_for_xero( $order ) {
        $first_name = $order->get_billing_first_name();
        $last_name = $order->get_billing_last_name();
        $email = $order->get_billing_email();
        $contact_name = trim( $first_name . ' ' . $last_name );

        // Fallback for contact name
        if ( empty( $contact_name ) ) {
             $contact_name = $email ?: 'Guest Checkout Customer WOO-' . $order->get_id();
        }

        // Fallback for email address
        if ( empty( $email ) ) {
            $email = 'unknown-' . $order->get_id() . '@example.com';
        }
        
        // Retrieve and format the addresses
        $billing_address = $this->format_address_for_xero( $order, 'billing', 'STREET' );
        $shipping_address = $this->format_address_for_xero( $order, 'shipping', 'STREET' );
        
        $contact_data = [
            // Ensure first and last name are separate fields for better Xero matching
            'FirstName'    => $first_name, 
            'LastName'     => $last_name,
            'Name'         => $contact_name,
            'EmailAddress' => $email,
            'Addresses'    => [],
        ];
        
        // Add Billing Address
        if ( ! empty( $billing_address ) ) {
            // Note: Xero uses Type STREET for a physical/primary address
            $contact_data['Addresses'][] = array_merge( $billing_address, [ 'AddressType' => 'STREET' ] );
        }

        // Add Shipping Address (only if it's different from billing or billing wasn't present)
        // We use the same 'STREET' type, Xero will recognize it as a second address.
        if ( ! empty( $shipping_address ) && $billing_address != $shipping_address ) {
            $contact_data['Addresses'][] = array_merge( $shipping_address, [ 'AddressType' => 'STREET' ] );
        }
        
        // Also include a Phone Number if available (Xero Contact optional fields)
        $phone_number = $order->get_billing_phone();
        if ( ! empty( $phone_number ) ) {
            $contact_data['Phones'][] = [
                'PhoneType'  => 'DEFAULT', // or 'MOBILE', 'FAX', 'DDI'
                'PhoneNumber' => $phone_number,
            ];
        }

        // If no addresses were added, remove the empty key from the final contact data
        if ( empty( $contact_data['Addresses'] ) ) {
            unset( $contact_data['Addresses'] );
        }

        return $contact_data;
    }
    
    /**
     * Attempts to retrieve a Xero Item by its Code (SKU).
     * @param string $sku The SKU of the WooCommerce product.
     * @param string $access_token
     * @param string $tenant_id
     * @return array|false Xero Item data or false if not found/error.
     */
    private function get_xero_item_by_code( $sku, $access_token, $tenant_id ) {
        $filter = urlencode( 'Code=="' . $sku . '"' );
        $endpoint = "Items?where={$filter}";
        $response = $this->xero_api_request( 'GET', $endpoint, $access_token, $tenant_id );

        if ( $response && ! empty( $response['Items'] ) ) {
            return $response['Items'][0];
        }
        return false;
    }

    /**
     * Creates a new Item in Xero based on the WooCommerce product data.
     * @param WC_Product $product The WooCommerce product object.
     * @param string $access_token
     * @param string $tenant_id
     * @return array|false Xero Item data or false on error.
     */
    private function create_xero_item( $product, $access_token, $tenant_id ) {
        // Use the configured default sales account for the new item
        $default_sales_account = get_option( 'xero_default_sales_account', '200' );

        $item_data = [
            'Code' => $product->get_sku(),
            'Name' => $product->get_name(),
            'IsSold' => true,
            'SalesDetails' => [
                'UnitPrice' => (float) $product->get_price(),
                'AccountCode' => $default_sales_account,
            ],
            // Note: PurchaseDetails are omitted as this is a sales sync.
        ];

        $response = $this->xero_api_request( 'POST', 'Items', $access_token, $tenant_id, [ 'Items' => [ $item_data ] ] );

        if ( $response && ! empty( $response['Items'][0]['ItemID'] ) ) {
            error_log( 'Xero Item Created successfully for SKU: ' . $product->get_sku() );
            return $response['Items'][0];
        }

        error_log( 'Xero Item Creation Failed for SKU: ' . $product->get_sku() );
        return false;
    }
    
    /**
     * Looks up an item by SKU, and creates it in Xero if it doesn't exist.
     * @param WC_Order_Item_Product $item
     * @param string $access_token
     * @param string $tenant_id
     * @return string|false The Xero Item Code (SKU) to be used, or false if not possible.
     */
    private function find_or_create_xero_item( $item, $access_token, $tenant_id ) {
        $product = $item->get_product();

        // Skip if it's not a standard product item or if the product has no SKU (SKU is mandatory for mapping)
        if ( ! $product || ! $product->get_sku() ) {
            return false;
        }

        $sku = $product->get_sku();

        // 1. Try to find existing item
        $xero_item = $this->get_xero_item_by_code( $sku, $access_token, $tenant_id );
        if ( $xero_item ) {
            return $xero_item['Code'];
        }

        // 2. Create item if not found
        $new_xero_item = $this->create_xero_item( $product, $access_token, $tenant_id );
        if ( $new_xero_item ) {
            return $new_xero_item['Code'];
        }

        // Fallback: If creation failed, we return false. The invoice will still be created, 
        // but the line item will not reference an ItemCode.
        return false;
    }

    /**
     * Prepares line items, including checking for and creating Xero Items based on SKU.
     * @param WC_Order $order
     * @param string $access_token
     * @param string $tenant_id
     * @return array Array of line items for Xero.
     */
    private function prepare_invoice_line_items( $order, $access_token, $tenant_id ) {
        // Ensure the default sales account is set for products
        $default_sales_account = get_option( 'xero_default_sales_account', '200' );

        $line_items = [];

        foreach ( $order->get_items() as $item ) {
            $item_code = $this->find_or_create_xero_item( $item, $access_token, $tenant_id );
            
            $line_item = [
                 'Description' => $item->get_name(),
                 'Quantity'    => (float) $item->get_quantity(),
                 'UnitAmount'  => (float) $order->get_item_total( $item, false, true ), // Price excluding tax
                 'AccountCode' => $default_sales_account,
                 'TaxAmount'   => (float) $item->get_total_tax(),
             ];
             
             if ( $item_code ) {
                 // Include ItemCode if the item was successfully found or created in Xero
                 $line_item['ItemCode'] = $item_code;
             }
             
             $line_items[] = $line_item;
        }

        // Handle shipping as a separate line item if present
        if ( $order->get_shipping_total() > 0 ) {
            $line_items[] = [
                'Description' => 'Shipping Cost (Order ID: ' . $order->get_id() . ')',
                'Quantity'    => 1,
                'UnitAmount'  => (float) $order->get_shipping_total(),
                'AccountCode' => $default_sales_account, 
                'TaxAmount'   => (float) $order->get_shipping_tax(), // Include shipping tax if present
            ];
        }

        return $line_items;
    }

    /**
     * Creates the invoice and registers payment.
     * @param WC_Order $order
     * @param array $contact_data Xero Contact details (Name and EmailAddress).
     * @param array $line_items Xero formatted line items.
     * @param string $access_token
     * @param string $tenant_id
     * @return bool True on success, false on failure.
     */
    private function create_and_register_paid_invoice( $order, $contact_data, $line_items, $access_token, $tenant_id ) {

        // 1. Prepare Invoice Data
        $invoice_data = [
            'Type'          => 'ACCREC', // Accounts Receivable (Sales Invoice)
            'Contact'       => $contact_data, // Only includes Name and EmailAddress
            'Date'          => date('Y-m-d', $order->get_date_created()->getTimestamp()),
            'DueDate'       => date('Y-m-d', $order->get_date_created()->getTimestamp()),
            'LineItems'     => $line_items,
            'Status'        => 'AUTHORISED', // Create as awaiting payment
            'Reference'     => $order->get_id(),
            'InvoiceNumber' => $order->get_order_number(),
            'LineAmountTypes' => 'Exclusive', 
        ];

        $shipping_address_1 = $order->get_shipping_address_1();
        $shipping_city = $order->get_shipping_city();

        // Only proceed if we have a primary shipping address or city
        if ( ! empty( $shipping_address_1 ) || ! empty( $shipping_city ) ) {
            
            $delivery_address = [
                // Required Xero fields for DeliveryAddress object
                'AttentionTo'  => trim( $order->get_shipping_first_name() . ' ' . $order->get_shipping_last_name() ),
                'AddressLine1' => $shipping_address_1,
                'AddressLine2' => $order->get_shipping_address_2(),
                'City'         => $shipping_city,
                'Region'       => $order->get_shipping_state(),
                'PostalCode'   => $order->get_shipping_postcode(),
                'Country'      => $order->get_shipping_country(),
            ];

            // Use array_filter to remove null or empty strings, ensuring only populated fields are sent.
            // This is crucial as Xero can reject objects with empty fields if they are mandatory or unexpected.
            $invoice_data['DeliveryAddress'] = array_filter( $delivery_address );

            // If the filter removes AttentionTo (e.g., if no name), Xero may complain. 
            // We ensure it falls back to the Contact Name if shipping name is empty.
            if ( empty( $invoice_data['DeliveryAddress']['AttentionTo'] ) ) {
                 $invoice_data['DeliveryAddress']['AttentionTo'] = $contact_data['Name'];
            }
        }
        error_log( 'XERO INVOICE PAYLOAD DEBUG: ' . print_r( $invoice_data['DeliveryAddress'], true ) );
        // 2. Create Invoice
        $invoice_response = $this->xero_api_request( 'POST', 'Invoices', $access_token, $tenant_id, [ 'Invoices' => [ $invoice_data ] ] );

        if ( ! $invoice_response || empty( $invoice_response['Invoices'][0]['InvoiceID'] ) ) {
            // Error logged by xero_api_request
            return false;
        }

        $invoice_id = $invoice_response['Invoices'][0]['InvoiceID'];
        
        // --- Payment Registration Logic ---
        
        $payment_method = $order->get_payment_method();
        $payment_mappings = get_option( 'xero_payment_mappings', [] );
        $bank_account_code = $payment_mappings[ $payment_method ] ?? null; // Fallback to null instead of '999'
        
        // If no bank account code is mapped, we skip payment registration but note the success of the invoice.
        if ( is_null( $bank_account_code ) || empty( $bank_account_code ) ) {
            $order->add_order_note( 
                'Xero Sync Successful (Invoice Created: ' . $invoice_id . '). Payment Skipped: WooCommerce payment method "' . $payment_method . 
                '" is **not mapped** to a Xero Bank Account Code in the plugin settings. Please configure mappings to register payments automatically.' 
            );
            return true; // Invoice was created successfully, so we consider the sync successful overall.
        }

        // 3. Register Payment
        $payment_data = [
            'Invoice'     => [ 'InvoiceID' => $invoice_id ],
            'Account'     => [ 'Code' => $bank_account_code ], // Xero Bank Account Code (mapped in settings)
            'Date'        => date('Y-m-d', time()), // Use current date for payment registration
            'Amount'      => $order->get_total(),
        ];

        $payment_response = $this->xero_api_request( 'POST', 'Payments', $access_token, $tenant_id, [ 'Payments' => [ $payment_data ] ] );

        if ( $payment_response ) {
            $order->add_order_note( 'Xero Sync Successful: Invoice ' . $invoice_id . ' created and marked as paid.' );
            return true;
        } else {
            // This is a failure of the payment step, but the invoice exists.
            $order->add_order_note( 'Xero Sync Partially Successful: Invoice ' . $invoice_id . ' created, but Payment Registration Failed (Check Xero Account Code for ' . $bank_account_code . ').' );
            return true;
        }
    }
}
