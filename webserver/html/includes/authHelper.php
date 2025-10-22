<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class AuthHelper implements IAuthHelper
{
    private ILogger $logger;
    private IEnv $env;

    private string $route;

    public function __construct(
        ILogger $logger = null,
        ISystem $system = new SystemWrapper(),
        IEnv $env = new Env()
    )
    {
        $this->route = "/authHelper";

        $this->logger = $logger ?? new Logger(route: $this->route, system: $system);
        $this->env = $env;
    }

    public function getAuthHeaders($contentType = null)
    {
        $PROXMOX_API_TOKEN = $this->env['PROXMOX_API_TOKEN'] ?? null;

        if ($PROXMOX_API_TOKEN === null) {
            $this->logger->logError("PROXMOX_API_TOKEN is not set in environment variables.");
            throw new CustomException("PROXMOX_API_TOKEN is not set in environment variables.");
        }

        $headers = [
            "Authorization: PVEAPIToken=$PROXMOX_API_TOKEN"
        ];

        if ($contentType !== null) {
            $headers[] = "Content-Type: $contentType";
        }

        return $headers;
    }

    public function getBackendHeaders($contentType = 'application/json'): array
    {
        $BACKEND_AUTHENTICATION_TOKEN = $this->env['BACKEND_AUTHENTICATION_TOKEN'] ?? null;

        return [
            'Content-Type: ' . $contentType,
            'Authentication-Token: ' . $BACKEND_AUTHENTICATION_TOKEN
        ];
    }
}

