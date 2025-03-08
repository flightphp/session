<?php

declare(strict_types=1);

namespace flight;

use SessionHandlerInterface;

/**
 * A lightweight, file-based session handler for the Flight framework.
 * Supports non-blocking behavior, optional encryption, and auto-commit.
 */
class Session implements SessionHandlerInterface
{
    private string $savePath;
    private array $data = [];
    private bool $changed = false;
    private ?string $sessionId = null;
    private ?string $encryptionKey = null;
    private bool $autoCommit = true;
    private bool $testMode = false;

    /**
     * Constructor to initialize the session handler.
     *
     * @param array $config Configuration options:
     *      - save_path: Directory where session files are stored (default: system temp dir/flight_sessions)
     *      - encryption_key: Optional encryption key for session data (recommended 32 bytes for AES-256)
     *      - auto_commit: Whether to auto-commit session changes on shutdown (default: true)
     *      - start_session: Whether to start the session automatically (default: true)
     *      - test_mode: Run in test mode without altering PHP's session state (default: false)
     *      - test_session_id: Custom session ID to use in test mode (default: random ID)
     */
    public function __construct(array $config = [])
    {
        $this->savePath = $config['save_path'] ?? sys_get_temp_dir() . '/flight_sessions';
        $this->encryptionKey = $config['encryption_key'] ?? null;
        $this->autoCommit = $config['auto_commit'] ?? true;
        $startSession = $config['start_session'] ?? true;
        $this->testMode = $config['test_mode'] ?? false;
        
        // Set test session ID if provided
        if ($this->testMode === true && isset($config['test_session_id'])) {
            $this->sessionId = $config['test_session_id'];
        }

        // Set the save path, defaulting to a subdirectory in the system temp directory
        if (is_dir($this->savePath) === false) {
            mkdir($this->savePath, 0700, true); // Secure permissions: owner-only access
        }

        // Initialize session handler
        $this->initializeSession($startSession);
    }
    
    /**
     * Initialize the session handler and optionally start the session.
     *
     * @param bool $startSession Whether to start the session automatically
     * @return void
     */
    private function initializeSession(bool $startSession): void
    {
        // In test mode, generate a test session ID if none was provided
        if ($this->testMode) {
            if ($this->sessionId === null) {
                $this->sessionId = bin2hex(random_bytes(16)); // Generate a test session ID
            }
			$this->read($this->sessionId); // Load session data for the test session ID
            return; // Skip actual session operations in test mode
        }
        
		// @codeCoverageIgnoreStart
        // Register the session handler only if no session is active yet
        if ($startSession === true && session_status() === PHP_SESSION_NONE) {
            session_set_save_handler($this, true);
            
            // Start the session if requested
            session_start(['read_and_close' => true]);
            $this->sessionId = session_id();
        } elseif (session_status() === PHP_SESSION_ACTIVE) {
            // If session is already active, ensure we have the session ID
            $this->sessionId = session_id();
        }

        // Register auto-commit on shutdown if enabled
        if ($this->autoCommit === true) {
            register_shutdown_function([$this, 'commit']);
        }
		// @codeCoverageIgnoreEnd
    }

	
	/**
	 * Open a session.
	 *
	 * This method is called by PHP when a session is started. It initializes the session storage.
	 *
	 * @param string $savePath The path where to store/retrieve the session.
	 * @param string $sessionName The name of the session.
	 * @return bool Returns true always
	 */
    public function open($savePath, $sessionName): bool
    {
        return true;
    }

	/**
	 * Closes the current session.
	 *
	 * This method is called automatically when the script ends or when session_write_close() is called.
	 *
	 * @return bool Returns true always
	 */
    public function close(): bool
    {
        return true;
    }

	/**
	 * Reads the session data associated with the given session ID.
	 *
	 * @param string $id The session ID.
	 * @return string The session data.
	 */
    public function read($id): string
	{
		$this->sessionId = $id;
		$file = $this->getSessionFile($id);

		// Fail fast: no file exists
		if (file_exists($file) === false) {
			$this->data = [];
			return serialize($this->data);
		}

		// Fail fast: unable to read file or empty content
		$content = file_get_contents($file);
		if ($content === false || strlen($content) < 1) {
			$this->data = [];
			return serialize($this->data);
		}

		// Extract prefix and data
		$prefix = $content[0];
		$dataStr = substr($content, 1);

		// Handle plain data (no encryption)
		if ($prefix === 'P' && $this->encryptionKey === null) {
			$this->data = unserialize($dataStr) ?: [];
			return serialize($this->data);
		}

		// Handle encrypted data
		if ($prefix === 'E' && $this->encryptionKey !== null) {

			$iv = substr($dataStr, 0, 16);
			$encrypted = substr($dataStr, 16);
			$decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $this->encryptionKey, 0, $iv);

			$this->data = $decrypted !== false ? unserialize($decrypted) : [];
			return serialize($this->data);
		}

		// Fail fast: mismatch between prefix and encryption state
		$this->data = [];
		return serialize($this->data);
	}

    /**
     * Helper method for encryption to make testing easier.
     * Protected visibility to allow mocking in tests.
     *
     * @param string $data Data to encrypt
     * @return string|false Encrypted data or false on failure
     */
    protected function encryptData(string $data)
    {
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $this->encryptionKey, 0, $iv);
        
        if ($encrypted === false) {
            return false; // @codeCoverageIgnore
        }
        
        return 'E' . $iv . $encrypted;
    }

    /**
     * Modify the write method to use the encryptData helper method
     */
    public function write($id, $data): bool
    {
        // Fail fast: no changes to write
        if ($this->changed === false) {
            return true;
        }

        $file = $this->getSessionFile($id);
        $serialized = serialize($this->data);

        // Handle encryption if key is provided
        if ($this->encryptionKey !== null) {
            $content = $this->encryptData($serialized);
            
            // Fail fast: encryption failed
            if ($content === false) {
                return false;
            }
        } else {
            $content = 'P' . $serialized;
        }

        // Write to file and return success
        return file_put_contents($file, $content) !== false;
    }

	/**
	 * Destroys the session with the given ID.
	 *
	 * @param string $id The ID of the session to destroy.
	 * @return bool Returns true on success or false on failure.
	 */
    public function destroy($id): bool
    {
        $file = $this->getSessionFile($id);
        if (file_exists($file)) {
            unlink($file);
        }
        $this->data = [];
        $this->changed = true;
        return true;
    }

	/**
	 * Garbage collector for session data.
	 *
	 * This method is responsible for cleaning up old session data that has
	 * exceeded the maximum lifetime.
	 *
	 * @param int $maxLifetime The maximum lifetime of a session in seconds.
	 * @return int|false The number of deleted sessions on success, or false on failure.
	 */
    public function gc($maxLifetime)
	{
		$count = 0;
		$time = time();
		$pattern = $this->savePath . '/sess_*';

		// Get session files; return 0 if glob fails or no files exist
		$files = glob($pattern);
		foreach ($files as $file) {
			if (filemtime($file) + $maxLifetime < $time) {
				if (unlink($file)) {
					$count++;
				}
			}
		}

		return $count;
	}

	/**
	 * Sets a session variable.
	 *
	 * @param string $key The name of the session variable.
	 * @param mixed $value The value to be stored in the session variable.
	 * @return self Returns the current instance for method chaining.
	 */
    public function set(string $key, $value): self
    {
        $this->data[$key] = $value;
        $this->changed = true;
        return $this;
    }

	/**
	 * Retrieve a value from the session.
	 *
	 * @param string $key The key of the session value to retrieve.
	 * @param mixed $default The default value to return if the key does not exist. Default is null.
	 * @return mixed The value associated with the given key, or the default value if the key does not exist.
	 */
    public function get(string $key, $default = null)
    {
        return $this->data[$key] ?? $default;
    }

	/**
	 * Deletes a session variable.
	 *
	 * @param string $key The key of the session variable to delete.
	 * @return self Returns the current instance for method chaining.
	 */
    public function delete(string $key): self
    {
        unset($this->data[$key]);
        $this->changed = true;
        return $this;
    }

	/**
	 * Clears all session data.
	 *
	 * @return self Returns the current instance for method chaining.
	 */
    public function clear(): self
    {
        $this->data = [];
        $this->changed = true;
        return $this;
    }

	/**
	 * Retrieve all session data.
	 *
	 * @return array An associative array containing all session data.
	 */
	public function getAll(): array
	{
		return $this->data;
	}

	/**
	 * Commits the current session data and writes it to the storage.
	 *
	 * This method should be called to ensure that all session data is properly
	 * saved and the session is closed. It is typically called at the end of a
	 * request to persist any changes made to the session.
	 *
	 * @return void
	 */
    public function commit(): void
    {
        if ($this->changed && $this->sessionId) {
            $this->write($this->sessionId, '');
            $this->changed = false;
        }
    }

	/**
	 * Get the current session ID.
	 *
	 * @return string|null The session ID if one exists, or null if no session is active.
	 */
    public function id(): ?string
    {
        return $this->sessionId;
    }

	/**
	 * Regenerates the session ID.
	 *
	 * @param bool $deleteOld Whether to delete the old session data or not.
	 * @return self Returns the current instance for method chaining.
	 */
    public function regenerate(bool $deleteOld = false): self
    {
        if ($this->sessionId) {
            if ($this->testMode) {
                // In test mode, simply generate a new ID without affecting PHP sessions
                $oldId = $this->sessionId;
                $this->sessionId = bin2hex(random_bytes(16));
                if ($deleteOld) {
                    $this->destroy($oldId);
                }
            } else {
				// @codeCoverageIgnoreStart
                session_regenerate_id($deleteOld);
                $newId = session_id();
                if ($deleteOld) {
                    $this->destroy($this->sessionId);
                }
                $this->sessionId = $newId;
				// @codeCoverageIgnoreEnd
            }
            $this->changed = true;
        }
        return $this;
    }

	/**
	 * Retrieves the file path for the session file based on the session ID.
	 *
	 * @param string $id The session ID.
	 * @return string The file path for the session file.
	 */
    private function getSessionFile(string $id): string
    {
        return $this->savePath . '/sess_' . $id;
    }
}