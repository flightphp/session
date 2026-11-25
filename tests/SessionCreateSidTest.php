<?php

namespace tests;

use flight\Session;
use PHPUnit\Framework\TestCase;

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

    public function testCreateSidReturns32CharHex(): void
    {
        $session = $this->makeSession();
        $id = $session->create_sid();

        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $id);
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

    /**
     * Under use_strict_mode (as the library starts sessions), an unknown
     * attacker-chosen ID must be rejected and replaced.
     */
    public function testStrictModeRejectsUnknownSessionId(): void
    {
        $src = realpath(__DIR__ . '/../src/Session.php');
        $this->assertNotFalse($src);

        $unknownId = '0123456789abcdef0123456789abcdef';
        $script = <<<'PHP'
require $argv[1];
$unknownId = $argv[2];
$savePath = $argv[3];
if (is_dir($savePath) === false) {
    mkdir($savePath, 0700, true);
}
session_id($unknownId);
$session = new flight\Session([
    'save_path' => $savePath,
    'auto_commit' => false,
    'start_session' => true,
    'test_mode' => false
]);
$newId = (string) $session->id();
if (session_status() === PHP_SESSION_ACTIVE) {
    session_abort();
}
echo json_encode(['unknown' => $unknownId, 'new' => $newId]);
PHP;

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
            $script,
            $src,
            $unknownId,
            $this->tempDir,
        ];
        $process = proc_open($cmd, $descriptorSpec, $pipes);
        $this->assertIsResource($process);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $status = proc_close($process);

        $this->assertSame(0, $status, $stderr);
        $payload = json_decode($stdout, true);
        $this->assertIsArray($payload, $stdout . $stderr);
        $this->assertNotSame($unknownId, $payload['new']);
        $this->assertNotSame('', $payload['new']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $payload['new']);
    }
}
