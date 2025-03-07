# FlightPHP Session
[![Latest Stable Version](http://poser.pugx.org/flightphp/session/v)](https://packagist.org/packages/flightphp/session)
[![License](https://poser.pugx.org/flightphp/session/license)](https://packagist.org/packages/flightphp/session)
[![PHP Version Require](http://poser.pugx.org/flightphp/session/require/php)](https://packagist.org/packages/flightphp/session)
[![Dependencies](http://poser.pugx.org/flightphp/session/dependents)](https://packagist.org/packages/flightphp/session)

A lightweight, file-based session handler for the Flight framework. It supports non-blocking behavior, optional encryption, and auto-commit functionality. See [basic example](#basic-example).

## Installation

Simply install with Composer

```bash
composer require flightphp/session
```

## Basic Example

Let's see how easy it is to use FlightPHP Session:

```php
// Create a session instance with default settings
$session = new flight\Session();

// Store some data
$session->set('user_id', 123);
$session->set('username', 'johndoe');
$session->set('is_admin', false);

// Retrieve data
echo $session->get('username'); // Outputs: johndoe

// Use a default value if the key doesn't exist
echo $session->get('preferences', 'default_theme'); // Outputs: default_theme

// Remove a session value
$session->delete('is_admin');

// Check if a value exists
if ($session->get('user_id')) {
    echo 'User is logged in!';
}

// Clear all session data
$session->clear();
```

## Advanced Configuration

You can customize the session handler with various configuration options:

```php
$session = new flight\Session([
    'save_path' => '/custom/path/to/sessions', // Custom directory for storing session files
    'encryption_key' => 'your-secret-32-byte-key', // Enable encryption with a secure key
    'auto_commit' => true, // Automatically commit session changes on shutdown
    'start_session' => true, // Start the session automatically
    'test_mode' => false, // Enable for testing without affecting PHP's session state
]);
```

## Session Security

When dealing with sensitive user data, it's recommended to use encryption:

```php
// Create a session with encryption enabled
$session = new flight\Session([
    'encryption_key' => 'a-secure-32-byte-key-for-aes-256-cbc',
]);

// Now all session data will be automatically encrypted when stored
$session->set('credit_card', '4111-1111-1111-1111');
```

## Session Regeneration

For security purposes, you might want to regenerate the session ID periodically:

```php
// Regenerate the session ID and keep the current session data
$session->regenerate();

// Regenerate the session ID and delete the old session data
$session->regenerate(true);
```

## Documentation

Head over to the [documentation page](https://docs.flightphp.com/awesome-plugins/session) to learn more about usage and how cool this thing is! :)

## License

MIT
