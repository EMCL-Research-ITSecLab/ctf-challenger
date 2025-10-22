<?php
declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use PHPUnit\Framework\TestCase;

class RegistrationHandlerTest extends TestCase
{
    private PDO $pdo;
    private array $generalConfig;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;
    private IAuthHelper $authHelper;
    private ICurlHelper $curlHelper;

    private ISession $session;
    private IServer $server;
    private IPost $post;

    private ISystem $system;
    private IEnv $env;

    private $mockDB;

    public function setUp(): void {
        $this->databaseHelper = $this->createMock(IDatabaseHelper::class);
        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->logger = new MockLogger();
        $this->authHelper = $this->createMock(IAuthHelper::class);
        $this->curlHelper = $this->createMock(ICurlHelper::class);

        $this->session = new MockSession();
        $this->server = new MockServer();
        $this->post = new MockPost();

        $this->system = new SystemWrapper();
        $this->env = new MockEnv();

        $this->generalConfig = json_decode($this->system->file_get_contents(__DIR__ . '/../../config/general.config.json'), true);

        // Mock PDO for database interactions
        $this->mockDB = null;
    }

    private function requireMockDB(): void {
        $this->mockDB = new MockPostgresDB();
        $this->pdo = $this->mockDB->getPDO();
        $this->databaseHelper = $this->createMock(IDatabaseHelper::class);
        $this->databaseHelper->method('getPDO')->willReturn($this->pdo);
    }

    public function testInvalidRequestMethodThrowsException(): void {
        $this->server['REQUEST_METHOD'] = 'GET';

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid request method');
        $this->expectExceptionCode(405);

        new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
    }

    public function testInvalidCsrfTokenThrowsException(): void {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'invalid-token';
        $this->post['username'] = 'testuser2';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(false);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertStringContainsString('Invalid CSRF token', $json['message']);
        $this->assertEquals(403, $json['error_code']);
    }

    public function testMissingUsernameThrowsException(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();

        $json = json_decode($output, true);
        $this->assertFalse($json['success']);
        $this->assertStringContainsString('All fields are required', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testMissingEmailThrowsException(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'existinguser';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();

        $json = json_decode($output, true);
        $this->assertFalse($json['success']);
        $this->assertStringContainsString('All fields are required', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testMissingPasswordThrowsException(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'existinguser';
        $this->post['email'] = 'test2@test.test';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();

        $json = json_decode($output, true);
        $this->assertFalse($json['success']);
        $this->assertStringContainsString('All fields are required', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testMissingConfirmPasswordThrowsException(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'existinguser';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();

        $json = json_decode($output, true);
        $this->assertFalse($json['success']);
        $this->assertStringContainsString('All fields are required', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testTooLongUsernameThrowsException(): void {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = str_repeat('a', $this->generalConfig['user']['MAX_USERNAME_LENGTH'] + 1);
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();

        $json = json_decode($output, true);
        $this->assertFalse($json['success']);
        $this->assertStringContainsString('Username must not exceed', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testTooShortUsernameThrowsException(): void {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = str_repeat('a', $this->generalConfig['user']['MIN_USERNAME_LENGTH'] - 1);
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();

        $json = json_decode($output, true);
        $this->assertFalse($json['success']);
        $this->assertStringContainsString('Username must be at least', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testInvalidCharsUsernameThrowsException(): void {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';

        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        $invalid_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=', '{', '}', '[', ']', '|', '\\', ':', ';', '"', '\'', '<', '>', ',', '.', '?', '/', ' '];

        $username = str_repeat('a', max($this->generalConfig['user']['MIN_USERNAME_LENGTH'] - 2, 1));

        foreach ($invalid_chars as $char) {
            $this->post['username'] = $username . $char . 'a';

            ob_start();
            $handler = new RegistrationHandler(
                $this->generalConfig,
                $this->databaseHelper,
                $this->securityHelper,
                $this->logger,
                $this->authHelper,
                $this->curlHelper,
                $this->session,
                $this->server,
                $this->post,
                $this->system,
                $this->env
            );
            $handler->handleRequest();
            $output = ob_get_clean();

            $json = json_decode($output, true);
            $this->assertFalse($json['success'], "Failed asserting that username with char '$char' is invalid.");
            $this->assertStringContainsString('Username contains invalid characters', $json['message']);
            $this->assertEquals(400, $json['error_code']);
        }
    }

    public function testTooLongEmailThrowsException(): void {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'testuser2';
        $this->post['email'] = str_repeat('a', $this->generalConfig['user']['MAX_EMAIL_LENGTH'] + 1) . '@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();

        $json = json_decode($output, true);
        $this->assertFalse($json['success']);
        $this->assertStringContainsString('Email must not exceed', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testInvalidEmailFormatThrowsException(): void {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'testuser2';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        $invalidEmails = [
            'plainaddress',
            '@no-local-part.com',
            'test@.com',
            'test@com',
            'test@site..com'
        ];

        foreach ($invalidEmails as $email) {
            $this->post['email'] = $email;

            ob_start();
            $handler = new RegistrationHandler(
                $this->generalConfig,
                $this->databaseHelper,
                $this->securityHelper,
                $this->logger,
                $this->authHelper,
                $this->curlHelper,
                $this->session,
                $this->server,
                $this->post,
                $this->system,
                $this->env
            );
            $handler->handleRequest();
            $output = ob_get_clean();

            $json = json_decode($output, true);
            $this->assertFalse($json['success'], "Failed asserting that email '$email' is invalid.");
            $this->assertStringContainsString('Invalid email format', $json['message']);
            $this->assertEquals(400, $json['error_code']);
        }
    }

    public function testTooShortPasswordThrowsException(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'testuser2';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = str_repeat('a', $this->generalConfig['user']['MIN_PASSWORD_LENGTH'] - 1);
        $this->post['confirm-password'] = str_repeat('a', $this->generalConfig['user']['MIN_PASSWORD_LENGTH'] - 1);

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();

        $json = json_decode($output, true);
        $this->assertFalse($json['success']);
        $this->assertStringContainsString('Password must be at least', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testTooLongPasswordThrowsException(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'testuser2';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = str_repeat('a', $this->generalConfig['user']['MAX_PASSWORD_LENGTH'] + 1);
        $this->post['confirm-password'] = str_repeat('a', $this->generalConfig['user']['MAX_PASSWORD_LENGTH'] + 1);

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();

        $json = json_decode($output, true);
        $this->assertFalse($json['success']);
        $this->assertStringContainsString('Password must not exceed', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testMismatchedPasswordsThrowException(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'testuser2';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = str_repeat('a', $this->generalConfig['user']['MIN_PASSWORD_LENGTH']);
        $this->post['confirm-password'] = str_repeat('b', $this->generalConfig['user']['MIN_PASSWORD_LENGTH']);

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();

        $json = json_decode($output, true);
        $this->assertFalse($json['success']);
        $this->assertStringContainsString('Passwords do not match', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testNullReturnIdOnUserAccountCreationThrowsExceptionAndRollsBack(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'newuser';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        $stmtMock = $this->createMock(PDOStatement::class);
        $stmtMock->method('execute')->willReturn(true);
        $stmtMock->method('fetchColumn')->willReturn(null);

        $pdo = $this->createMock(PDO::class);
        $pdo->method('beginTransaction')->willReturn(true);
        $pdo->method('prepare')->willReturn($stmtMock);
        $this->databaseHelper = $this->createMock(IDatabaseHelper::class);
        $this->databaseHelper->method('getPDO')->willReturn($pdo);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);


        $this->assertFalse($json['success']);
        $this->assertStringContainsString('Account creation failed', $json['message']);
        $this->assertEquals(500, $json['error_code']);
    }

    public function testErrorDuringVpnIpAssignmentThrowsExceptionAndRollsBack(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'newuser';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        $stmtMock = $this->createMock(PDOStatement::class);
        $stmtMock->method('execute')->willReturn(true);
        $stmtMock->method('fetch')->willReturnOnConsecutiveCalls(
            false, // username duplicate check
            false, // email duplicate check
            [
                'user_id' => 1,
                'vpn_static_ip' => null
        ]);

        $pdo = $this->createMock(PDO::class);
        $pdo->method('beginTransaction')->willReturn(true);
        $pdo->method('rollBack')->willReturn(true);
        $pdo->method('prepare')->willReturn($stmtMock);
        $pdo->method('commit')->willThrowException(new PDOException());

        $this->databaseHelper = $this->createMock(IDatabaseHelper::class);
        $this->databaseHelper->method('getPDO')->willReturn($pdo);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertStringContainsString('Account creation failed', $json['message']);
        $this->assertEquals(500, $json['error_code']);
    }

    public function testErrorDuringVpnSavingThrowsExceptionAndRollsBack(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'newuser';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        $stmtMock = $this->createMock(PDOStatement::class);
        $stmtMock->method('execute')->willReturn(true);
        $stmtMock->method('fetch')->willReturnOnConsecutiveCalls(false, false, ['user_id' => 2, 'vpn_static_ip' => '1.2.3.4']); // First call returns user ID, second call returns null for VPN
        $stmtMock->method('rowCount')->willReturn(1);

        $pdo = $this->createMock(PDO::class);
        $pdo->method('beginTransaction')->willReturn(true);
        $pdo->method('rollBack')->willReturn(true);
        $pdo->method('prepare')->willReturn($stmtMock);

        $this->databaseHelper = $this->createMock(IDatabaseHelper::class);
        $this->databaseHelper->method('getPDO')->willReturn($pdo);

        $systemMock = $this->createMock(ISystem::class);
        $systemMock->method('file_exists')->willReturn(true);
        $systemMock->method('mkdir')->willReturn(true);
        $systemMock->method('file_put_contents')->willReturn(false);

        $curlHelperMock = $this->createMock(ICurlHelper::class);
        $curlHelperMock->method('makeBackendRequest')->willReturn([
            'success' => true,
            'headers' => ['content-type' => 'application/octet-stream'],
            'response' => 'dummy-vpn-config'
        ]);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $curlHelperMock,
            $this->session,
            $this->server,
            $this->post,
            $systemMock,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertStringContainsString('VPN setup incomplete', $json['message']);
        $this->assertEquals(500, $json['error_code']);
    }

    public function testErrorDuringVpnConfigDirCreationThrowsExceptionAndRollsBack(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'newuser';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        $stmtMock = $this->createMock(PDOStatement::class);
        $stmtMock->method('execute')->willReturn(true);
        $stmtMock->method('fetch')->willReturnOnConsecutiveCalls(false, false, ['user_id' => 1, 'vpn_static_ip' => '1.2.3.4']); // First call returns user ID, second call returns null for VPN
        $stmtMock->method('rowCount')->willReturn(1);

        $pdo = $this->createMock(PDO::class);
        $pdo->method('beginTransaction')->willReturn(true);
        $pdo->method('rollBack')->willReturn(true);
        $pdo->method('prepare')->willReturn($stmtMock);

        $this->databaseHelper = $this->createMock(IDatabaseHelper::class);
        $this->databaseHelper->method('getPDO')->willReturn($pdo);

        $systemMock = $this->createMock(ISystem::class);
        $systemMock->method('file_exists')->willReturn(false);
        $systemMock->method('mkdir')->willReturn(false);

        $curlHelperMock = $this->createMock(ICurlHelper::class);
        $curlHelperMock->method('makeBackendRequest')->willReturn([
            'success' => true,
            'headers' => ['content-type' => 'application/octet-stream'],
            'response' => 'dummy-vpn-config'
        ]);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $curlHelperMock,
            $this->session,
            $this->server,
            $this->post,
            $systemMock,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertStringContainsString('VPN setup incomplete', $json['message']);
        $this->assertEquals(500, $json['error_code']);
    }


    public function testErrorDuringVpnGenerationThrowsExceptionAndRollsBack(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'newuser';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        $stmtMock = $this->createMock(PDOStatement::class);
        $stmtMock->method('execute')->willReturn(true);
        $stmtMock->method('fetch')->willReturnOnConsecutiveCalls(false, false, ['user_id' => 1, 'vpn_static_ip' => '1.2.3.4']); // First call returns user ID, second call returns null for VPN

        $pdo = $this->createMock(PDO::class);
        $pdo->method('beginTransaction')->willReturn(true);
        $pdo->method('rollBack')->willReturn(true);
        $pdo->method('prepare')->willReturn($stmtMock);

        $this->databaseHelper = $this->createMock(IDatabaseHelper::class);
        $this->databaseHelper->method('getPDO')->willReturn($pdo);

        $systemMock = $this->createMock(ISystem::class);
        $systemMock->method('file_exists')->willReturn(true);
        $systemMock->method('mkdir')->willReturn(true);
        $systemMock->method('file_put_contents')->willReturn(false);

        $curlHelperMock = $this->createMock(ICurlHelper::class);
        $curlHelperMock->method('makeBackendRequest')->willReturn([
            'success' => true,
            'headers' => ['content-type' => 'application/something-else'],
            'response' => json_encode([
                'error' => 'VPN generation error'
            ])
        ]);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $curlHelperMock,
            $this->session,
            $this->server,
            $this->post,
            $systemMock,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertStringContainsString('VPN setup incomplete', $json['message']);
        $this->assertEquals(500, $json['error_code']);
    }

    public function testSomethingUnexpectedHappenedDuringVpnGenerationThrowsExceptionAndRollsBack(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'newuser';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        $stmtMock = $this->createMock(PDOStatement::class);
        $stmtMock->method('execute')->willReturn(true);
        $stmtMock->method('fetch')->willReturnOnConsecutiveCalls(
            false, // username duplicate check
            false, // email duplicate check
            [
                'user_id' => 1,
                'vpn_static_ip' => '1.2.3.4'
        ]);
        $pdo = $this->createMock(PDO::class);
        $pdo->method('beginTransaction')->willReturn(true);
        $pdo->method('rollBack')->willReturn(true);
        $pdo->method('prepare')->willReturn($stmtMock);

        $this->databaseHelper = $this->createMock(IDatabaseHelper::class);
        $this->databaseHelper->method('getPDO')->willReturn($pdo);

        $systemMock = $this->createMock(ISystem::class);
        $systemMock->method('file_exists')->willReturn(true);
        $systemMock->method('mkdir')->willReturn(true);
        $systemMock->method('file_put_contents')->willReturn(false);

        $curlHelperMock = $this->createMock(ICurlHelper::class);
        $curlHelperMock->method('makeBackendRequest')->willReturn([
            'success' => true,
            'headers' => ['content-type' => 'application/something-else'],
            'response' => json_encode([
                'definitely-not-an-error' => 'some value'
            ])
        ]);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $curlHelperMock,
            $this->session,
            $this->server,
            $this->post,
            $systemMock,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertStringContainsString('VPN setup incomplete', $json['message']);
        $this->assertEquals(500, $json['error_code']);
    }

    public function testUnexpectedResponseFromVpnGenerationThrowsExceptionAndRollsBack(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'newuser';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        $stmtMock = $this->createMock(PDOStatement::class);
        $stmtMock->method('execute')->willReturn(true);
        $stmtMock->method('fetch')->willReturnOnConsecutiveCalls(
            false, // username duplicate check
            false, // email duplicate check
            [
                'user_id' => 1,
                'vpn_static_ip' => '1.2.3.4'
        ]);
        $stmtMock->method('rowCount')->willReturn(1);

        $pdo = $this->createMock(PDO::class);
        $pdo->method('beginTransaction')->willReturn(true);
        $pdo->method('rollBack')->willReturn(true);
        $pdo->method('prepare')->willReturn($stmtMock);

        $this->databaseHelper = $this->createMock(IDatabaseHelper::class);
        $this->databaseHelper->method('getPDO')->willReturn($pdo);

        $systemMock = $this->createMock(ISystem::class);
        $systemMock->method('file_exists')->willReturn(true);
        $systemMock->method('mkdir')->willReturn(true);
        $systemMock->method('file_put_contents')->willReturn(false);

        $curlHelperMock = $this->createMock(ICurlHelper::class);
        $curlHelperMock->method('makeBackendRequest')->willReturn([
            'success' => true,
            'headers' => ['content-type' => 'application/something-else'],
            'response' => 'dummy-non-json-response'
        ]);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $curlHelperMock,
            $this->session,
            $this->server,
            $this->post,
            $systemMock,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertStringContainsString('VPN setup incomplete', $json['message']);
        $this->assertEquals(500, $json['error_code']);
    }

    public function testExceptionDuringVpnGenerationThrowsExceptionAndRollsBack(): void
    {
        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'newuser';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        $stmtMock = $this->createMock(PDOStatement::class);
        $stmtMock->method('execute')->willReturn(true);
        $stmtMock->method('fetch')->willReturnOnConsecutiveCalls(
            false, // username duplicate check
            false, // email duplicate check
            [
                'user_id' => 1,
                'vpn_static_ip' => '1.2.3.4'
        ]);
        $stmtMock->method('rowCount')->willReturn(1);

        $pdo = $this->createMock(PDO::class);
        $pdo->method('beginTransaction')->willReturn(true);
        $pdo->method('rollBack')->willReturn(true);
        $pdo->method('prepare')->willReturn($stmtMock);

        $this->databaseHelper = $this->createMock(IDatabaseHelper::class);
        $this->databaseHelper->method('getPDO')->willReturn($pdo);

        $systemMock = $this->createMock(ISystem::class);
        $systemMock->method('file_exists')->willReturn(true);
        $systemMock->method('mkdir')->willReturn(true);
        $systemMock->method('file_put_contents')->willReturn(false);

        $curlHelperMock = $this->createMock(ICurlHelper::class);
        $curlHelperMock->method('makeBackendRequest')->willThrowException(new Exception());

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $curlHelperMock,
            $this->session,
            $this->server,
            $this->post,
            $systemMock,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertStringContainsString('VPN setup incomplete', $json['message']);
        $this->assertEquals(500, $json['error_code']);
    }

    // Tests that require a mock DB

    public function testDoubleUsernameThrowsException(): void
    {
        $this->requireMockDB();

        $this->pdo->exec("
            INSERT INTO users (username, email, password_hash, password_salt)
            VALUES ('existinguser', 'test2@test.test', 'hashedpassword', 'somesalt')
        ");

        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'existinguser';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertStringContainsString('Username already taken', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testDoubleEmailThrowsException(): void
    {
        $this->requireMockDB();

        $this->pdo->exec("
            INSERT INTO users (username, email, password_hash, password_salt)
            VALUES ('existinguser', 'test2@test.test', 'hashedpassword', 'somesalt')
        ");

        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'existinguser2';
        $this->post['email'] = 'test2@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCSRFToken')->willReturn(true);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertStringContainsString('Email already registered', $json['message']);
        $this->assertEquals(400, $json['error_code']);
    }

    public function testSuccessfulRegistrationFlow(): void
    {
        $this->requireMockDB();

        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'newuser';
        $this->post['email'] = 'new@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCsrfToken')->willReturn(true);

        // mock VPN config API response
        $this->curlHelper = $this->createMock(ICurlHelper::class);
        $this->curlHelper->method('makeBackendRequest')->willReturn([
            'success' => true,
            'headers' => ['content-type' => 'application/octet-stream'],
            'response' => 'dummy-vpn-config'
        ]);

        $this->system = $this->createMock(ISystem::class);
        $this->system->method('file_exists')->willReturn(false);
        $this->system->method('mkdir')->willReturn(true);
        $this->system->method('file_put_contents')->willReturn(20);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertTrue($json['success']);
        $this->assertStringContainsString('Registration successful', $json['message']);
        $this->assertNotNull($json['user_id']);

        $userId = $json['user_id'];

        // Verify user is in the database
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = :id");
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $this->assertNotFalse($user);
        $this->assertEquals('newuser', $user['username']);
        $this->assertEquals('new@test.test', $user['email']);
        $this->assertNotEmpty($user['password_hash']);
        $this->assertNotEmpty($user['created_at']);
    }

    public function testVpnConfigGenerationFails(): void
    {
        $this->requireMockDB();

        $this->server['REQUEST_METHOD'] = 'POST';
        $this->post['csrf_token'] = 'valid-token';
        $this->post['username'] = 'vpnfailuser';
        $this->post['email'] = 'vpnfail@test.test';
        $this->post['password'] = 'Password1!';
        $this->post['confirm-password'] = 'Password1!';

        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->securityHelper->method('validateCsrfToken')->willReturn(true);

        $this->curlHelper = $this->createMock(ICurlHelper::class);
        $this->curlHelper->method('makeBackendRequest')->willReturn([
            'success' => false,
            'http_code' => 500
        ]);

        ob_start();
        $handler = new RegistrationHandler(
            $this->generalConfig,
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->authHelper,
            $this->curlHelper,
            $this->session,
            $this->server,
            $this->post,
            $this->system,
            $this->env
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertStringContainsString('VPN setup incomplete', $json['message']);
        $this->assertEquals(500, $json['error_code']);
    }
}