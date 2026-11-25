<?php

namespace tests;

use flight\Session;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class SessionCreateSidTest extends TestCase
{
    /** @var string Temporary directory for session files */
    private string $tempDir;

    /**
     * Set up the test environment by creating a temporary directory.
     */
    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/flight_session_sid_test_' . uniqid();
        if (!is_dir($this->tempDir)) {
            mkdir($this->tempDir, 0700);
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }

    /**
     * Clean up the temporary directory after each test.
     */
    protected function tearDown(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }

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
     * @return Session
     */
    private function makeSession(): Session
    {
        return new Session([
            'save_path' => $this->tempDir,
            'auto_commit' => false,
            'start_session' => false,
            'test_mode' => true
        ]);
    }

    /**
     * Allowed characters for a given session.sid_bits_per_character value.
     */
    private function charsetForBits(int $bits): string
    {
        $tab = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,-';
        return substr($tab, 0, 1 << $bits);
    }

    public function testCreateSidMatchesRuntimeIniFormat(): void
    {
        $session = $this->makeSession();
        $length = (int) ini_get('session.sid_length');
        $bits = (int) ini_get('session.sid_bits_per_character');
        $id = $session->create_sid();

        $this->assertSame($length, strlen($id));
        $this->assertMatchesRegularExpression(
            '/^[' . preg_quote($this->charsetForBits($bits), '/') . ']+$/',
            $id
        );
    }

    public function testCreateSidReturnsUniqueIds(): void
    {
        $session = $this->makeSession();
        $ids = [];
        for ($i = 0; $i < 10; $i++) {
            $ids[] = $session->create_sid();
        }
        $this->assertSame(count($ids), count(array_unique($ids)));
    }

    public function testGenerateSessionIdHonorsSixBitEncodingAndCustomLength(): void
    {
        $session = $this->makeSession();
        $method = (new ReflectionClass($session))->getMethod('generateSessionId');
        $method->setAccessible(true);

        $id = $method->invoke($session, 40, 6);
        $this->assertSame(40, strlen($id));
        $this->assertMatchesRegularExpression('/^[0-9a-zA-Z,-]+$/', $id);
    }

    public function testGenerateSessionIdHonorsFiveBitEncoding(): void
    {
        $session = $this->makeSession();
        $method = (new ReflectionClass($session))->getMethod('generateSessionId');
        $method->setAccessible(true);

        $id = $method->invoke($session, 32, 5);
        $this->assertSame(32, strlen($id));
        $this->assertMatchesRegularExpression('/^[0-9a-v]+$/', $id);
    }

    public function testGenerateSessionIdFallsBackForInvalidParameters(): void
    {
        $session = $this->makeSession();
        $reflection = new ReflectionClass($session);
        $method = $reflection->getMethod('generateSessionId');
        $method->setAccessible(true);

        $tooShort = $method->invoke($session, 10, 3);
        $this->assertSame(32, strlen($tooShort));
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $tooShort);

        $tooLong = $method->invoke($session, 300, 9);
        $this->assertSame(32, strlen($tooLong));
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $tooLong);
    }

    public function testValidateIdReturnsFalseForEmptyOrUnknownId(): void
    {
        $session = $this->makeSession();
        $this->assertFalse($session->validateId(''));
        $this->assertFalse($session->validateId('definitely-not-a-stored-session'));
    }

    public function testValidateIdReturnsTrueAfterCommitAndFalseAfterDestroy(): void
    {
        $session = $this->makeSession();
        $session->set('user', 'tester');
        $session->commit();
        $id = $session->id();
        $this->assertNotNull($id);
        $this->assertTrue($session->validateId($id));

        $session->destroy($id);
        $this->assertFalse($session->validateId($id));
    }

    public function testLoadingSessionClassEmitsNoHandlerWarnings(): void
    {
        $src = realpath(__DIR__ . '/../src/Session.php');
        $this->assertNotFalse($src);

        $descriptorSpec = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $cmd = [
            PHP_BINARY,
            '-d',
            'display_errors=1',
            '-d',
            'error_reporting=E_ALL',
            '-r',
            'require $argv[1]; echo "OK";',
            $src,
        ];
        $process = proc_open($cmd, $descriptorSpec, $pipes);
        $this->assertIsResource($process);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $status = proc_close($process);

        $this->assertSame(0, $status);
        $this->assertSame('OK', $stdout);
        $this->assertStringNotContainsString('create_sid()', $stderr);
        $this->assertStringNotContainsString('validateId()', $stderr);
        $this->assertStringNotContainsString('missing the', $stderr);
    }
}
