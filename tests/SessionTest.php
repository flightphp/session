<?php

namespace tests;

use flight\Session;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class SessionTest extends TestCase
{
    /** @var string Temporary directory for session files */
    private string $tempDir;

    /** @var string Encryption key for testing (must be 32 bytes for AES-256) */
    private string $encryptionKey = 'test-encryption-key-32-bytes-long';

    /**
     * Set up the test environment by creating a temporary directory.
     */
    protected function setUp(): void
    {
        // Create a unique temporary directory for session files
        $this->tempDir = sys_get_temp_dir() . '/flight_session_test_' . uniqid();
        if (!is_dir($this->tempDir)) {
            mkdir($this->tempDir, 0700);
        }

        // Ensure no active session exists from a previous test
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }

    /**
     * Clean up the temporary directory after each test.
     */
    protected function tearDown(): void
    {
        // Close any active session
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }

        // Remove the temporary directory and its contents
        $this->deleteDirectory($this->tempDir);
    }

    /**
     * Helper method to recursively delete a directory.
     */
    private function deleteDirectory(string $dir): void
    {
        if (is_dir($dir) === false) {
            return;
        }
        $files = glob($dir . '/*');
        foreach ($files as $file) {
            if (is_file($file) === true) {
                unlink($file);
            } elseif (is_dir($file) === true) {
                $this->deleteDirectory($file);
            }
        }
        rmdir($dir);
    }

    /**
     * Test that the constructor creates the session directory.
     */
    public function testConstructorCreatesDirectory(): void
    {
        $session = new Session([
            'save_path' => $this->tempDir,
            'start_session' => false,
            'test_mode' => true
        ]);
        $this->assertDirectoryExists($this->tempDir);
    }

    /**
     * Test setting, getting, deleting, and clearing session data.
     */
    public function testSetGetDeleteClear(): void
    {
        $session = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => null,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true
        ]); // No auto-commit
        $session->set('key', 'value');
        $this->assertEquals('value', $session->get('key'));

        $session->delete('key');
        $this->assertNull($session->get('key'));

        $session->set('key1', 'value1');
        $session->set('key2', 'value2');
        $session->clear();
        $this->assertNull($session->get('key1'));
        $this->assertNull($session->get('key2'));
    }

    /**
     * Test reading and writing session data without encryption.
     */
    public function testReadWriteWithoutEncryption(): void
    {
        // First session instance to write data
        $session1 = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => null,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => 'test_session_id1234'
        ]); // No encryption, no auto-commit
        $session1->set('key', 'value');
        $session1->commit();

        // Simulate a new request with a second instance
        $session2 = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => null,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => 'test_session_id1234'
        ]);
        $this->assertEquals('value', $session2->get('key'));
    }

    /**
     * Test reading and writing session data with encryption.
     */
    public function testReadWriteWithEncryption(): void
    {
        // First session instance with encryption
        $session1 = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => $this->encryptionKey,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => 'test_session_id1234'
        ]);
        $session1->set('key', 'secret');
        $session1->commit();

        // Simulate a new request with encryption
        $session2 = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => $this->encryptionKey,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => 'test_session_id1234'
        ]);
        $this->assertEquals('secret', $session2->get('key'));
    }

    /**
     * Test that auto-commit saves session data on shutdown.
     */
    public function testAutoCommit(): void
    {
        // Session with auto-commit enabled
        $session1 = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => null,
            'auto_commit' => true,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => 'test_session_id1234'
        ]);
        $session1->set('key', 'value');
        // No manual commit; simulate shutdown by calling commit() manually
        $session1->commit();

        // Simulate a new request
        $session2 = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => null,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => 'test_session_id1234'
        ]);
        $this->assertEquals('value', $session2->get('key'));
    }

    /**
     * Test garbage collection of expired session files.
     */
    public function testGarbageCollection(): void
    {
        $session = new Session([
            'save_path' => $this->tempDir,
            'start_session' => false,
            'test_mode' => true
        ]);
        $file = $this->tempDir . '/sess_testfile';

        // Create an expired session file
        file_put_contents($file, 'Ptest'); // Simple content with 'P' prefix
        touch($file, time() - 3600); // Set file to 1 hour old

        $result = $session->gc(1800); // Max lifetime of 30 minutes
        $this->assertEquals(1, $result); // Expect 1 file deleted
        $this->assertFileDoesNotExist($file);
    }

    public function testGarbageCollectionWithEmptyDirectory(): void
    {
        $session = new Session([
            'save_path' => $this->tempDir,
            'start_session' => false,
            'test_mode' => true
        ]);

        // Ensure the directory is empty
        $result = $session->gc(1800); // Max lifetime of 30 minutes
        $this->assertEquals(0, $result); // No files to delete
    }

    public function testGarbageCollectionWithNoExpiredFiles(): void
    {
        $session = new Session([
            'save_path' => $this->tempDir,
            'start_session' => false,
            'test_mode' => true
        ]);
        $file = $this->tempDir . '/sess_testfile';

        // Create a fresh session file
        file_put_contents($file, 'Ptest');
        touch($file, time()); // File is not expired

        $result = $session->gc(1800); // Max lifetime of 30 minutes
        $this->assertEquals(0, $result); // No files deleted
        $this->assertFileExists($file);
    }

    public function testGarbageCollectionWithInvalidPath(): void
    {
        // Use a non-existent subdirectory to simulate failure
        $session = new Session([
            'save_path' => $this->tempDir . '/nonexistent',
            'start_session' => false,
            'test_mode' => true
        ]);
        $result = $session->gc(1800);
        $this->assertEquals(0, $result); // Expect 0 on failure
    }

    public function testGarbageCollectionWithNonIntegerMaxLifetime(): void
    {
        $session = new Session([
            'save_path' => $this->tempDir,
            'start_session' => false,
            'test_mode' => true
        ]);
        $file = $this->tempDir . '/sess_testfile';

        // Create an expired session file
        file_put_contents($file, 'Ptest');
        touch($file, time() - 3600); // 1 hour old

        $result = $session->gc('1800'); // Pass a string instead of int
        $this->assertEquals(1, $result); // Should still work due to PHP's type juggling
        $this->assertFileDoesNotExist($file);
    }

    /**
     * Test regenerating the session ID while preserving data.
     */
    public function testRegenerateSessionId(): void
    {
        $session = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => null,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true
        ]);
        $oldId = $session->id();
        $session->set('key', 'value');
        $session->commit();

        $session->regenerate();
        $newId = $session->id();
        $this->assertNotEquals($oldId, $newId);
        $this->assertEquals('value', $session->get('key'));
    }

    /**
     * Test the open and close methods which are required by the SessionHandlerInterface.
     */
    public function testOpenAndClose(): void
    {
        $session = new Session([
            'save_path' => $this->tempDir,
            'test_mode' => true
        ]);

        // Using reflection to access these methods since they're normally called by PHP internally
        $reflector = new ReflectionClass($session);

        $openMethod = $reflector->getMethod('open');
        $openMethod->setAccessible(true);
        $this->assertTrue($openMethod->invoke($session, $this->tempDir, 'PHPSESSID'));

        $closeMethod = $reflector->getMethod('close');
        $closeMethod->setAccessible(true);
        $this->assertTrue($closeMethod->invoke($session));
    }

    /**
     * Test the destroy method to ensure it removes session data.
     */
    public function testDestroy(): void
    {
        $sessionId = 'test_destroy_session';
        $session = new Session([
            'save_path' => $this->tempDir,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);

        // Create session data
        $session->set('key', 'value');
        $session->commit();

        // Verify the file exists
        $sessionFile = $this->tempDir . '/sess_' . $sessionId;
        $this->assertFileExists($sessionFile);

        // Use reflection to access destroy method
        $reflector = new ReflectionClass($session);
        $destroyMethod = $reflector->getMethod('destroy');
        $destroyMethod->setAccessible(true);

        $result = $destroyMethod->invoke($session, $sessionId);
        $this->assertTrue($result);
        $this->assertFileDoesNotExist($sessionFile);

        // Check that internal data was cleared
        $this->assertNull($session->get('key'));
    }

    /**
     * Test reading from empty or invalid session files.
     */
    public function testReadWithInvalidContent(): void
    {
        $sessionId = 'test_invalid_content';
        $sessionFile = $this->tempDir . '/sess_' . $sessionId;

        // Create empty file
        file_put_contents($sessionFile, '');

        $session = new Session([
            'save_path' => $this->tempDir,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);

        // Data should be empty array when file is empty
        $this->assertNull($session->get('any_key'));

        // Try with invalid content too short for proper format
        file_put_contents($sessionFile, 'X');

        $session2 = new Session([
            'save_path' => $this->tempDir,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);

        $this->assertNull($session2->get('any_key'));
    }

    /**
     * Test mismatch between encryption state and file prefix.
     */
    public function testReadWithPrefixMismatch(): void
    {
        $sessionId = 'test_prefix_mismatch';
        $sessionFile = $this->tempDir . '/sess_' . $sessionId;

        // Create file with E prefix but we'll read without encryption key
        $data = serialize(['key' => 'value']);
        file_put_contents($sessionFile, 'E' . str_repeat('0', 16) . 'dummy_encrypted_data');

        $session = new Session([
            'save_path' => $this->tempDir,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);

        // Data should be empty when prefix doesn't match encryption state
        $this->assertNull($session->get('key'));

        // Now try P prefix with encryption
        file_put_contents($sessionFile, 'P' . serialize(['key' => 'value']));

        $session2 = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => $this->encryptionKey,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);

        // Data should be empty when prefix doesn't match encryption state
        $this->assertNull($session2->get('key'));
    }

    /**
     * Test write method with encryption failure.
     */
    public function testWriteWithEncryptionFailure(): void
    {
        // We need to mock openssl_encrypt to simulate failure
        $sessionId = 'test_encryption_failure';

        // Create a partial mock of the Session class
        $session = $this->getMockBuilder(Session::class)
            ->setConstructorArgs([
                [
                    'save_path' => $this->tempDir,
                    'encryption_key' => 'invalid_key_for_test',
                    'test_mode' => true,
                    'test_session_id' => $sessionId,
                    'serialization' => 'php'
                ]
            ])
            ->onlyMethods(['encryptData'])
            ->getMock();

        // Set up the mock to simulate encryption failure
        $session->method('encryptData')->willReturn(false);

        // Use reflection to make encryptData accessible and inject it
        $reflector = new ReflectionClass(Session::class);
        $writeMethod = $reflector->getMethod('write');
        $writeMethod->setAccessible(true);

        // Set some data and mark as changed
        $session->set('key', 'value');

        // Write should return false when encryption fails
        $result = $writeMethod->invoke($session, $sessionId, 'data');
        $this->assertFalse($result);
    }

    /**
     * Test write method when no changes were made.
     */
    public function testWriteWithNoChanges(): void
    {
        $sessionId = 'test_no_changes';

        $session = new Session([
            'save_path' => $this->tempDir,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);
        $session->set('key', 'value');
        $session->commit(); // Commit to mark as changed
        $result = $session->write($sessionId, '');
        $this->assertTrue($result);
    }

    public function testGetAll(): void
    {
        $session = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => null,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true
        ]);

        $session->set('key1', 'value1');
        $session->set('key2', 'value2');

        $expectedData = [
            'key1' => 'value1',
            'key2' => 'value2'
        ];

        $this->assertEquals($expectedData, $session->getAll());
    }

    /**
     * Test reading and writing session data with JSON serialization (default, no encryption).
     */
    public function testReadWriteJsonDefault(): void
    {
        $sessionId = 'json_default_id';
        $session1 = new Session([
            'save_path' => $this->tempDir,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);
        $session1->set('foo', 'bar');
        $session1->commit();

        $sessionFile = $this->tempDir . '/sess_' . $sessionId;
        $fileContents = file_get_contents($sessionFile);
        $this->assertSame('J', $fileContents[0]);
        $data = json_decode(substr($fileContents, 1), true);
        $this->assertEquals(['foo' => 'bar'], $data);

        $session2 = new Session([
            'save_path' => $this->tempDir,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);
        $this->assertEquals('bar', $session2->get('foo'));
    }

    /**
     * Test reading and writing session data with JSON serialization and encryption.
     */
    public function testReadWriteJsonWithEncryption(): void
    {
        $sessionId = 'json_enc_id';
        $session1 = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => $this->encryptionKey,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);
        $session1->set('foo', 'secret');
        $session1->commit();

        $sessionFile = $this->tempDir . '/sess_' . $sessionId;
        $fileContents = file_get_contents($sessionFile);
        $this->assertSame('F', $fileContents[0]);
        $iv = substr($fileContents, 1, 16);
        $encrypted = substr($fileContents, 17);
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $this->encryptionKey, 0, $iv);
        $this->assertNotFalse($decrypted);
        $data = json_decode($decrypted, true);
        $this->assertEquals(['foo' => 'secret'], $data);
        // Ensure encrypted data is not trivially readable
        $this->assertStringNotContainsString('secret', $encrypted);

        $session2 = new Session([
            'save_path' => $this->tempDir,
            'encryption_key' => $this->encryptionKey,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);
        $this->assertEquals('secret', $session2->get('foo'));
    }

    /**
     * Test reading and writing session data with PHP serialization (legacy, no encryption).
     */
    public function testReadWritePhpSerialization(): void
    {
        $sessionId = 'php_plain_id';
        $session1 = new Session([
            'save_path' => $this->tempDir,
            'serialization' => 'php',
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);
        $session1->set('foo', 'bar');
        $session1->commit();

        $sessionFile = $this->tempDir . '/sess_' . $sessionId;
        $fileContents = file_get_contents($sessionFile);
        $this->assertSame('P', $fileContents[0]);
        $data = unserialize(substr($fileContents, 1));
        $this->assertEquals(['foo' => 'bar'], $data);

        $session2 = new Session([
            'save_path' => $this->tempDir,
            'serialization' => 'php',
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);
        $this->assertEquals('bar', $session2->get('foo'));
    }

    /**
     * Test reading and writing session data with PHP serialization and encryption (legacy).
     */
    public function testReadWritePhpWithEncryption(): void
    {
        $sessionId = 'php_enc_id';
        $session1 = new Session([
            'save_path' => $this->tempDir,
            'serialization' => 'php',
            'encryption_key' => $this->encryptionKey,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);
        $session1->set('foo', 'secret');
        $session1->commit();

        $sessionFile = $this->tempDir . '/sess_' . $sessionId;
        $fileContents = file_get_contents($sessionFile);
        $this->assertSame('E', $fileContents[0]);
        $iv = substr($fileContents, 1, 16);
        $encrypted = substr($fileContents, 17);
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $this->encryptionKey, 0, $iv);
        $this->assertNotFalse($decrypted);
        $data = unserialize($decrypted);
        $this->assertEquals(['foo' => 'secret'], $data);
        // Ensure encrypted data is not trivially readable
        $this->assertStringNotContainsString('secret', $encrypted);

        $session2 = new Session([
            'save_path' => $this->tempDir,
            'serialization' => 'php',
            'encryption_key' => $this->encryptionKey,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => $sessionId
        ]);
        $this->assertEquals('secret', $session2->get('foo'));
    }

    /**
     * Test that storing an object with JSON serialization throws an exception.
     */
    public function testJsonSerializationRejectsObjects(): void
    {
        $session = new Session([
            'save_path' => $this->tempDir,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true,
            'test_session_id' => 'json_obj_id'
        ]);
        $this->expectException(\InvalidArgumentException::class);
        $session->set('obj', new \stdClass());
        $session->commit();
    }

    public function testInvalidSerializationThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Session([
            'save_path' => $this->tempDir,
            'serialization' => 'invalid',
            'test_mode' => true
        ]);
    }

    public function testRegenerateInTestModeChangesId(): void
    {
        $session = new Session([
            'save_path' => $this->tempDir,
            'test_mode' => true
        ]);
        $oldId = $session->id();
        $session->regenerate();
        $newId = $session->id();
        $this->assertNotEquals($oldId, $newId);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $newId);
    }

    public function testAssertNoObjectsWithDeepArrayNoObjects(): void
    {
        $session = new \flight\Session([
            'save_path' => $this->tempDir,
            'test_mode' => true
        ]);
        // Should not throw
        $session->set('deep', [[['foo' => 'bar'], ['baz' => 123]], []]);
        $session->commit();
        $this->assertEquals([[['foo' => 'bar'], ['baz' => 123]], []], $session->get('deep'));
    }

    public function testAssertNoObjectsWithObjectNested(): void
    {
        $session = new \flight\Session([
            'save_path' => $this->tempDir,
            'test_mode' => true
        ]);
        $nested = [[['foo' => new \stdClass()]]];
        $this->expectException(\InvalidArgumentException::class);
        $session->set('deep', $nested);
        $session->commit();
    }

    public function testAssertNoObjectsWithEmptyArray(): void
    {
        $session = new \flight\Session([
            'save_path' => $this->tempDir,
            'test_mode' => true
        ]);
        $session->set('empty', []);
        $session->commit();
        $this->assertEquals([], $session->get('empty'));
    }

    public function testAssertNoObjectsWithObjectInMixedArray(): void
    {
        $session = new \flight\Session([
            'save_path' => $this->tempDir,
            'test_mode' => true
        ]);
        $mixed = ['a' => 1, 'b' => [2, new \stdClass()]];
        $this->expectException(\InvalidArgumentException::class);
        $session->set('mixed', $mixed);
        $session->commit();
    }

    public function testAssertNoObjectsWithPrimitive(): void
    {
        $session = new \flight\Session([
            'save_path' => $this->tempDir,
            'test_mode' => true
        ]);
        $session->set('primitive', 42);
        $session->commit();
        $this->assertEquals(42, $session->get('primitive'));
    }
}
