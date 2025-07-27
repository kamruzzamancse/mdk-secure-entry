<?php
/**
 * Plugin Name: Secure Entry
 * Description: A custom login and registration system for WordPress with additional features like role-based access control.
 * Version: 1.0
 * Author: Md. Kamruzzaman
 * Author URI: https://kamruzzaman.great-site.net/
 */

// Make sure WordPress is not being accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Register activation and deactivation hooks
function mdk_secure_entry_activation() {
    // Create custom roles
    add_role('realtor', 'Realtor', ['read' => true]);
    add_role('client', 'Client', ['read' => true]);
}
register_activation_hook(__FILE__, 'mdk_secure_entry_activation');

function mdk_secure_entry_deactivation() {
    remove_role('realtor');
    remove_role('client');
}
register_deactivation_hook(__FILE__, 'mdk_secure_entry_deactivation');


// Enqueue custom styles for the registration form
function mdk_enqueue_styles_debug() {
    wp_enqueue_style('mdk-secure-entry-styles', plugin_dir_url(__FILE__) . 'assets/css/mdk-secure-entry.css', array(), null);
}
add_action('wp_enqueue_scripts', 'mdk_enqueue_styles_debug');


// Redirect to WordPress built-in password reset page
function mdk_password_reset_redirect() {
    return wp_login_url() . '?action=lostpassword';
}
add_filter('lostpassword_url', 'mdk_password_reset_redirect', 10, 1);


// Shortcode for displaying the custom registration form
function mdk_registration_form() {
    if (is_user_logged_in()) {
        return 'You are already registered and logged in.';
    }

    ob_start();

    // Show error message if present
    if (isset($_GET['mdk_error'])) {
        echo '<div class="mdk-error-message" style="color: red;">' . esc_html($_GET['mdk_error']) . '</div>';
    }
    ?>
    <form method="post" action="" class="mdk-registration-form">
        <?php wp_nonce_field('mdk_register_action', 'mdk_register_nonce'); ?>
        <input type="text" name="mdk_username" placeholder="Username" required />
        <input type="email" name="mdk_email" placeholder="Email" required />
        <input type="password" name="mdk_password" placeholder="Password" required />
        <input type="password" name="mdk_confirm_password" placeholder="Confirm Password" required />
        
        <label for="mdk_user_role">Select your role:</label>
        <select name="mdk_user_role" id="mdk_user_role">
            <option value="realtor">Realtor</option>
            <option value="client">Client</option>
        </select>

        <button type="submit" name="mdk_register_submit">Register</button>

        <!-- Login link -->
        <p class="mdk-login-link">
            Already have an account? <a href="<?php echo esc_url( home_url('/login/') ); ?>">Login here</a>.
        </p>
    </form>
    <?php
    return ob_get_clean();
}
add_shortcode('mdk_registration_form', 'mdk_registration_form');

// registration form handler
function mdk_handle_registration_submission() {
    if (
        isset($_POST['mdk_register_submit']) &&
        isset($_POST['mdk_register_nonce']) &&
        wp_verify_nonce($_POST['mdk_register_nonce'], 'mdk_register_action')
    ) {
        $username = sanitize_user($_POST['mdk_username']);
        $email = sanitize_email($_POST['mdk_email']);
        $password = $_POST['mdk_password'];
        $confirm_password = $_POST['mdk_confirm_password'];
        $user_role = sanitize_text_field($_POST['mdk_user_role']);

        if (strlen($password) < 8) {
            wp_redirect(add_query_arg('mdk_error', 'Password must be at least 8 characters.', wp_get_referer()));
            exit;
        }

        if ($password !== $confirm_password) {
            wp_redirect(add_query_arg('mdk_error', 'Passwords do not match.', wp_get_referer()));
            exit;
        }

        if (username_exists($username)) {
            wp_redirect(add_query_arg('mdk_error', 'Username already exists.', wp_get_referer()));
            exit;
        }

        if (email_exists($email)) {
            wp_redirect(add_query_arg('mdk_error', 'Email already registered.', wp_get_referer()));
            exit;
        }

        $user_id = wp_create_user($username, $password, $email);

        if (is_wp_error($user_id)) {
            wp_redirect(add_query_arg('mdk_error', 'Registration failed. Try again.', wp_get_referer()));
            exit;
        }

        $user = new WP_User($user_id);

        if (in_array($user_role, ['realtor', 'client'])) {
            $user->set_role($user_role);
        } else {
            $user->set_role('subscriber');
        }

        wp_send_new_user_notifications($user_id, 'user');

        wp_safe_redirect(home_url('/login/'));
        exit;
    }
}
add_action('template_redirect', 'mdk_handle_registration_submission');


// Shortcode for displaying the custom login form
function mdk_login_form() {
    if (is_user_logged_in()) {
        return 'You are already logged in.';
    }

    ob_start(); // Start output buffering
    ?>
    <form method="post" action="" class="mdk-login-form">
        <?php wp_nonce_field('mdk_login_action', 'mdk_login_nonce'); ?> <!-- Nonce field for security -->
        <input type="text" name="mdk_login_username" placeholder="Username or Email" required />
        <input type="password" name="mdk_login_password" placeholder="Password" required />
        
        <!-- Remember Me Option -->
        <label><input type="checkbox" name="mdk_login_remember" /> Remember Me</label>
        
        <button type="submit" name="mdk_login_submit">Login</button>

        <!-- Forgot Password Link -->
        <p><a href="<?php echo wp_lostpassword_url(); ?>">Forgot Password?</a></p>

        <!-- Registration Link -->
        <p><a href="<?php echo home_url('/registration/'); ?>">Don't have an account? Register here</a></p>
    </form>
    <?php
    // Handle form submission
    if (isset($_POST['mdk_login_submit'])) {
        // Check nonce for security
        if (isset($_POST['mdk_login_nonce']) && wp_verify_nonce($_POST['mdk_login_nonce'], 'mdk_login_action')) {

            // Sanitize inputs to prevent XSS and other vulnerabilities
            $username = sanitize_text_field($_POST['mdk_login_username']);
            $password = sanitize_text_field($_POST['mdk_login_password']);
            $remember = isset($_POST['mdk_login_remember']) ? true : false; // Remember me checkbox

            // Login credentials
            $creds = array(
                'user_login'    => $username,
                'user_password' => $password,
                'remember'      => $remember
            );

            // Attempt login
            $user = wp_signon($creds, false);

            // Check if login was successful
            if (is_wp_error($user)) {
                echo '<div class="error-message">Login failed: ' . $user->get_error_message() . '</div>';
            } else {
                // Redirect user based on their role
                if (current_user_can('administrator')) {
                    wp_redirect(admin_url()); // Admin dashboard
                } elseif (current_user_can('realtor')) {
                    wp_redirect(home_url('/realtor-dashboard')); // Realtor dashboard
                } elseif (current_user_can('client')) {
                    wp_redirect(home_url('/client-dashboard')); // Client dashboard
                } else {
                    wp_redirect(home_url()); // Default redirect if no role matches
                }
                exit;
            }
        } else {
            echo '<div class="error-message">Security check failed. Please try again.</div>';
        }
    }
    return ob_get_clean();
}
add_shortcode('mdk_login_form', 'mdk_login_form');


// Redirect users after successful login based on their role
function mdk_login_redirect($redirect_to, $request, $user) {
    // Check if the user is a Realtor or Client
    if (in_array('realtor', (array) $user->roles)) {
        return home_url('/realtor-dashboard'); // Redirect Realtors to Realtor Dashboard
    } elseif (in_array('client', (array) $user->roles)) {
        return home_url('/client-dashboard'); // Redirect Clients to Client Dashboard
    } elseif (in_array('administrator', (array) $user->roles)) {
        return admin_url(); // Redirect Admin to the WordPress Admin Dashboard
    }

    return $redirect_to; // Default redirection if no specific role matched
}
add_filter('login_redirect', 'mdk_login_redirect', 10, 3);


// Custom Password Reset Form (Shortcode)
function mdk_password_reset_form() {
    ob_start();
    ?>
    <form method="post" action="">
        <input type="email" name="mdk_reset_email" placeholder="Enter your email" required />
        <button type="submit" name="mdk_reset_submit">Reset Password</button>
    </form>
    <?php
    // Handle password reset form submission
    if (isset($_POST['mdk_reset_submit'])) {
        $email = sanitize_email($_POST['mdk_reset_email']);
        
        // Check if the email exists in the system
        if (email_exists($email)) {
            $user = get_user_by('email', $email);
            $reset_link = wp_lostpassword_url();

            // Send password reset email
            wp_mail($email, 'Password Reset Request', 'Click the following link to reset your password: ' . $reset_link);
            echo 'A password reset link has been sent to your email.';
        } else {
            echo 'No user found with that email address.';
        }
    }
    return ob_get_clean();
}
add_shortcode('mdk_password_reset', 'mdk_password_reset_form');

// Track failed login attempts
function mdk_limit_login_attempts($username) {
    $max_attempts = 3; // Max attempts before blocking
    $lockout_time = 60 * 15; // Lockout for 15 minutes
    $failed_attempts = get_transient('mdk_failed_attempts_' . $username);

    if ($failed_attempts >= $max_attempts) {
        $lockout = get_transient('mdk_lockout_' . $username);
        if ($lockout) {
            echo 'Your account has been locked due to multiple failed login attempts. Please try again later.';
            exit;
        }
    }

    $failed_attempts++;
    set_transient('mdk_failed_attempts_' . $username, $failed_attempts, $lockout_time);
}

add_action('wp_login_failed', 'mdk_limit_login_attempts');


// Send a custom password reset email
function mdk_send_password_reset_email($email) {
    $reset_link = wp_lostpassword_url();
    $subject = 'Password Reset Request';
    $message = 'We received a request to reset your password. Please click the link below to reset your password: ' . $reset_link;

    wp_mail($email, $subject, $message);
}


