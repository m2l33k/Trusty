// -----------------------------------------------------------------------
// BlockGuard.UI - Services/ConfigurationService.cs
// Reads and writes the BlockGuard appsettings.json configuration.
// -----------------------------------------------------------------------

using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BlockGuard.UI.Services;

/// <summary>
/// Manages reading and writing the BlockGuard configuration file (appsettings.json).
/// Provides methods to add/remove protected paths and persist changes.
/// </summary>
public sealed class ConfigurationService
{
    private readonly string _configPath;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public ConfigurationService()
    {
        // Look for appsettings.json relative to the UI executable,
        // or in the Agent project directory during development
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        _configPath = Path.Combine(baseDir, "appsettings.json");

        // Fallback: look in the Agent project directory
        if (!File.Exists(_configPath))
        {
            var devPath = FindAgentConfigPath();
            if (devPath != null)
            {
                _configPath = devPath;
            }
        }
    }

    public ConfigurationService(string configPath)
    {
        _configPath = configPath;
    }

    public string ConfigPath => _configPath;

    /// <summary>
    /// Loads the full config as a dictionary for modification.
    /// </summary>
    public async Task<AppConfig> LoadAsync()
    {
        if (!File.Exists(_configPath))
        {
            return new AppConfig
            {
                BlockGuard = new BlockGuardConfig
                {
                    ProtectedPaths = [],
                    AuthorizedProcesses = [],
                    IdentityCacheTtlSeconds = 30,
                    HandleTimeoutSeconds = 60,
                    AuditLogPath = @"C:\ProgramData\BlockGuard\Logs\audit.json",
                    EnableDpapiEncryption = true,
                    DpapiScope = "LocalMachine"
                }
            };
        }

        var json = await File.ReadAllTextAsync(_configPath);
        var config = JsonSerializer.Deserialize<AppConfig>(json, JsonOptions);
        return config ?? new AppConfig { BlockGuard = new BlockGuardConfig() };
    }

    /// <summary>
    /// Saves the entire configuration back to disk.
    /// </summary>
    public async Task SaveAsync(AppConfig config)
    {
        var json = JsonSerializer.Serialize(config, JsonOptions);
        var dir = Path.GetDirectoryName(_configPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        await File.WriteAllTextAsync(_configPath, json);
    }

    /// <summary>
    /// Tries to find the Agent's appsettings.json during development.
    /// </summary>
    private static string? FindAgentConfigPath()
    {
        // Walk up from the current directory looking for the solution
        var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
        while (dir != null)
        {
            var slnFiles = dir.GetFiles("BlockGuard.sln");
            if (slnFiles.Length > 0)
            {
                var agentConfig = Path.Combine(dir.FullName, "src", "BlockGuard.Agent", "appsettings.json");
                if (File.Exists(agentConfig))
                    return agentConfig;
            }
            dir = dir.Parent;
        }
        return null;
    }
}

// ----- Configuration Models (match appsettings.json structure) -----

public sealed class AppConfig
{
    [JsonPropertyName("Logging")]
    public LoggingConfig? Logging { get; set; }

    [JsonPropertyName("BlockGuard")]
    public BlockGuardConfig BlockGuard { get; set; } = new();
}

public sealed class LoggingConfig
{
    [JsonPropertyName("LogLevel")]
    public Dictionary<string, string>? LogLevel { get; set; }
}

public sealed class BlockGuardConfig
{
    [JsonPropertyName("ProtectedPaths")]
    public List<string> ProtectedPaths { get; set; } = [];

    [JsonPropertyName("AuthorizedProcesses")]
    public List<AuthorizedProcessConfig> AuthorizedProcesses { get; set; } = [];

    [JsonPropertyName("IdentityCacheTtlSeconds")]
    public int IdentityCacheTtlSeconds { get; set; } = 30;

    [JsonPropertyName("HandleTimeoutSeconds")]
    public int HandleTimeoutSeconds { get; set; } = 60;

    [JsonPropertyName("AuditLogPath")]
    public string AuditLogPath { get; set; } = @"C:\ProgramData\BlockGuard\Logs\audit.json";

    [JsonPropertyName("EnableDpapiEncryption")]
    public bool EnableDpapiEncryption { get; set; } = true;

    [JsonPropertyName("DpapiScope")]
    public string DpapiScope { get; set; } = "LocalMachine";
}

public sealed class AuthorizedProcessConfig
{
    [JsonPropertyName("RuleName")]
    public string RuleName { get; set; } = "";

    [JsonPropertyName("ExecutablePath")]
    public string? ExecutablePath { get; set; }

    [JsonPropertyName("ExpectedFileHash")]
    public string? ExpectedFileHash { get; set; }

    [JsonPropertyName("ExpectedSignerSubject")]
    public string? ExpectedSignerSubject { get; set; }

    [JsonPropertyName("MinimumIntegrityLevel")]
    public string MinimumIntegrityLevel { get; set; } = "Medium";

    [JsonPropertyName("RequireSignature")]
    public bool RequireSignature { get; set; } = false;
}
