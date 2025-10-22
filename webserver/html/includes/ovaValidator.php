<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class OvaValidator implements IOvaValidator
{
    private array $config;
    private string $route;

    private ILogger $logger;
    private ISystem $system;

    public function __construct(
        array $config = null,
        ILogger $logger = null,
        ISystem $system = new SystemWrapper()
    )
    {
        if ($config === null)
            $config = require __DIR__ . '/../config/backend.config.php';

        $this->route = "/ovaValidator";

        $this->logger = $logger ?? new Logger(route: $this->route, system: $system);
        $this->config = $config['upload'] ?? [];
        $this->logger->logDebug("Initialized OvaValidator");
        $this->system = $system;
    }

    public function validate(string $ovaPath): void
    {
        $maxVirtualSizeBytes = $this->config['MAX_VIRTUAL_SIZE_BYTES'];
        $maxSingleVmdkSizeBytes = $this->config['MAX_SINGLE_VMDK_SIZE_BYTES'];
        $maxTotalVmdkSizeBytes = $this->config['MAX_TOTAL_VMDK_SIZE_BYTES'];
        $maxVmdkCount = $this->config['MAX_VMDK_COUNT'];
        $maxOvfSizeBytes = $this->config['MAX_OVF_SIZE_BYTES'];


        $this->validateInputFile($ovaPath);

        $tmpDir = $this->system->sys_get_temp_dir() . '/ova_check_' . uniqid();
        if (!$this->system->mkdir($tmpDir, 0755, true)) {
            $this->logger->logError("Failed to create temp directory: " . $tmpDir);
            throw new CustomException("System error during validation", 500);
        }

        try {
            $output = $this->listOvaContents($ovaPath);
            $ovfFile = $this->findAndValidateOvfFile($output, $maxOvfSizeBytes);
            $ovfPath = $this->extractOvfFile($ovaPath, $tmpDir, $ovfFile['name']);
            $xml = $this->parseOvfFile($ovfPath);
            $disks = $this->extractDiskInformation($xml);
            $this->validateVirtualDisks($disks, $maxVirtualSizeBytes);
            $this->findAndValidateVmdkFiles($output, $maxSingleVmdkSizeBytes, $maxTotalVmdkSizeBytes, $maxVmdkCount);
            $this->logger->logDebug("OVA validation completed successfully");
        } finally {
            $this->cleanupTempDir($tmpDir);
        }
    }

    private function validateInputFile(string $ovaPath): void
    {
        if (!$this->system->file_exists($ovaPath)) {
            $this->logger->logError("OVA file does not exist: " . $ovaPath);
            throw new CustomException("Invalid OVA file", 400);
        }

        if (!$this->system->is_readable($ovaPath)) {
            $this->logger->logError("OVA file is not readable: " . $ovaPath);
            throw new CustomException("Cannot read OVA file", 403);
        }
    }

    private function listOvaContents(string $ovaPath): array
    {
        $cmd = "tar -tvf " . escapeshellarg($ovaPath) . " 2>&1";
        exec($cmd, $output, $ret);

        if ($ret !== 0) {
            $errorOutput = implode("\n", array_slice($output, 0, 5));
            $this->logger->logError("Failed to list OVA contents. Command: " . $cmd . " Output: " . $errorOutput);
            throw new CustomException("Invalid OVA file format", 400);
        }

        return $output;
    }

    private function findAndValidateOvfFile(array $output, int $maxOvfSizeBytes): array
    {
        $pattern = '/^\S+\s+\S+\/\S+\s+(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(.+\.ovf)$/i';
        $ovfFiles = [];

        foreach ($output as $line) {
            if (preg_match($pattern, $line, $matches)) {
                $size = (int)$matches[1];
                $filename = basename($matches[2]);

                if ($filename !== $matches[2]) {
                    $this->logger->logError("Suspicious OVF filename detected: " . $matches[2]);
                    throw new CustomException("Invalid OVF filename", 400);
                }

                if ($size > $maxOvfSizeBytes) {
                    $this->logger->logError("OVF file too large: " . $filename . " (" . $this->formatBytes($size) . ")");
                    throw new CustomException("OVF file exceeds size limit", 400);
                }

                $ovfFiles[] = ['name' => $filename, 'size' => $size];
            }
        }

        if (count($ovfFiles) === 0) {
            $this->logger->logError("No OVF file found in OVA");
            throw new CustomException("No OVF file found in OVA package", 400);
        }

        if (count($ovfFiles) > 1) {
            $this->logger->logError("Multiple OVF files found in OVA");
            throw new CustomException("Multiple OVF files found - only one allowed", 400);
        }
        return $ovfFiles[0];
    }

    private function extractOvfFile(string $ovaPath, string $tmpDir, string $ovfName): string
    {
        $cmd = "tar -xf " . escapeshellarg($ovaPath) . " -C " . escapeshellarg($tmpDir) . " " . escapeshellarg($ovfName) . " 2>&1";
        exec($cmd, $output, $ret);

        if ($ret !== 0) {
            $errorOutput = implode("\n", array_slice($output, 0, 5));
            $this->logger->logError("Failed to extract OVF file. Command: " . $cmd . " Output: " . $errorOutput);
            throw new CustomException("Failed to extract OVF from OVA", 400);
        }

        $ovfPath = $tmpDir . DIRECTORY_SEPARATOR . basename($ovfName);
        if (!$this->system->file_exists($ovfPath)) {
            $this->logger->logError("Extracted OVF file not found at expected path: " . $ovfPath);
            throw new CustomException("System error during OVF extraction", 500);
        }

        return $ovfPath;
    }

    private function parseOvfFile(string $ovfPath): SimpleXMLElement
    {
        $ovfContent = $this->system->file_get_contents($ovfPath);
        if ($ovfContent === false) {
            $this->logger->logError("Failed to read OVF file: " . $ovfPath);
            throw new CustomException("Failed to read OVF contents", 500);
        }

        if (str_contains($ovfContent, '<!ENTITY')) {
            $this->logger->logError("OVF contains potential XXE vulnerability (ENTITY declaration)");
            throw new CustomException("Invalid OVF file - security violation", 400);
        }

        libxml_use_internal_errors(true);
        $xml = simplexml_load_string($ovfContent);
        if ($xml === false) {
            $errors = libxml_get_errors();
            $errorMessages = array_map(fn($e) => $e->message, $errors);
            libxml_clear_errors();

            $this->logger->logError("Invalid OVF XML: " . implode(", ", array_slice($errorMessages, 0, 3)));
            throw new CustomException("Invalid OVF XML format", 400);
        }

        try {
            $xml->registerXPathNamespace('ovf', 'http://schemas.dmtf.org/ovf/envelope/1');
        } catch (CustomException $e) {
            $this->logger->logError("Failed to register OVF namespace: " . $e->getMessage());
            throw new CustomException("Invalid OVF namespace", 400);
        } catch (Exception $e) {
            $this->logger->logError("Unexpected error registering OVF namespace: " . $e->getMessage());
            throw new Exception('Internal Server Error', 500);
        }

        return $xml;
    }

    private function extractDiskInformation(SimpleXMLElement $xml): array
    {
        $disks = [];
        try {
            $diskNodes = $xml->xpath('//ovf:Disk') ?: [];
            foreach ($diskNodes as $disk) {
                $attrs = $disk->attributes('ovf', true) ?: $disk->attributes();

                if (!isset($attrs['capacity'])) {
                    $this->logger->logError("Disk element missing capacity attribute");
                    throw new CustomException("Invalid OVF - disk capacity missing", 400);
                }

                $capacity = (int)$attrs['capacity'];
                $units = strtolower((string)($attrs['capacityAllocationUnits'] ?? 'byte'));

                $size = match ($units) {
                    'byte', 'bytes' => $capacity,
                    'kb', 'kilobytes' => $capacity * 1024,
                    'mb', 'megabytes', 'byte * 2^20' => $capacity * 1024 ** 2,
                    'gb', 'gigabytes' => $capacity * 1024 ** 3,
                    'tb', 'terabytes' => $capacity * 1024 ** 4,
                    default => throw new CustomException("Unsupported capacity unit: $units", 400),
                };

                if ($size <= 0) {
                    $this->logger->logError("Invalid disk size: " . $size);
                    throw new CustomException("Invalid disk size in OVF", 400);
                }

                $disks[] = $size;
            }
        } catch (CustomException $e) {
            $this->logger->logError("Error parsing disk information: " . $e->getMessage());
            throw $e;
        } catch (Exception $e) {
            $this->logger->logError("Unexpected error parsing disk information: " . $e->getMessage());
            throw new Exception('Internal Server Error', 500);
        }

        return $disks;
    }

    private function validateVirtualDisks(array $disks, int $maxVirtualSizeBytes): void
    {
        $declaredVirtualSize = array_sum($disks);
        if ($declaredVirtualSize > $maxVirtualSizeBytes) {
            $this->logger->logError("Declared virtual size exceeds limit: " . $this->formatBytes($declaredVirtualSize));
            throw new CustomException("Virtual disk size exceeds maximum allowed", 400);
        }
    }

    private function findAndValidateVmdkFiles(array $output, int $maxSingleVmdkSizeBytes, int $maxTotalVmdkSizeBytes, int $maxVmdkCount): void
    {
        $pattern = '/^\S+\s+\S+\/\S+\s+(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(.+\.vmdk)$/i';
        $vmdkFiles = [];

        foreach ($output as $line) {
            if (preg_match($pattern, $line, $matches)) {
                $size = (int)$matches[1];
                $filename = basename($matches[2]);

                if ($filename !== $matches[2]) {
                    $this->logger->logError("Suspicious VMDK path detected: " . $matches[2]);
                    throw new CustomException("Invalid VMDK filename", 400);
                }

                $vmdkFiles[$filename] = $size;
            }
        }

        if (count($vmdkFiles) > $maxVmdkCount) {
            $this->logger->logError("Too many VMDK files: " . count($vmdkFiles));
            throw new CustomException("Too many disk files in OVA", 400);
        }

        $totalVmdkSize = array_sum($vmdkFiles);
        if ($totalVmdkSize > $maxTotalVmdkSizeBytes) {
            $this->logger->logError("Total VMDK size exceeds limit: " . $this->formatBytes($totalVmdkSize));
            throw new CustomException("Total disk size exceeds maximum allowed", 400);
        }

        foreach ($vmdkFiles as $filename => $size) {
            if ($size > $maxSingleVmdkSizeBytes) {
                $this->logger->logError("VMDK file exceeds size limit: " . $filename . " (" . $this->formatBytes($size) . ")");
                throw new CustomException("Disk file exceeds maximum allowed size", 400);
            }
        }
    }

    private function cleanupTempDir(string $tmpDir): void
    {
        if ($this->system->is_dir($tmpDir)) {
            try {
                $this->system->system("rm -rf " . escapeshellarg($tmpDir));
            } catch (CustomException $e) {
                $this->logger->logError("Failed to clean up temp directory: " . $tmpDir . " - " . $e->getMessage());
            } catch (Exception $e) {
                $this->logger->logError("Unexpected error cleaning up temp directory: " . $tmpDir . " - " . $e->getMessage());
            }
        }
    }

    private function formatBytes(int $bytes, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= (1 << (10 * $pow));
        return round($bytes, $precision) . ' .php' . $units[$pow];
    }
}