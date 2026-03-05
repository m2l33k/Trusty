// -----------------------------------------------------------------------
// BlockGuard.Agent - BlockGuardService.cs
// The main orchestrating Windows Service that coordinates all three layers.
// -----------------------------------------------------------------------

using BlockGuard.Core.Configuration;
using BlockGuard.Core.Interfaces;
using BlockGuard.Core.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BlockGuard.Agent;

/// <summary>
/// The core background service that:
/// 1. Locks down protected files via ACLs at startup
/// 2. Starts ETW monitoring for file access events
/// 3. Evaluates access attempts against the security policy
/// 4. Logs all decisions via the audit logger
/// 5. Grants temporary access handles for authorized processes
/// </summary>
public sealed class BlockGuardService : BackgroundService
{
    private readonly ILogger<BlockGuardService> _logger;
    private readonly BlockGuardOptions _options;
    private readonly IFileAccessMonitor _monitor;
    private readonly IPolicyEvaluator _policyEvaluator;
    private readonly IAclEnforcer _aclEnforcer;
    private readonly IAuditLogger _auditLogger;
    private readonly IDpapiWrapper _dpapiWrapper;

    public BlockGuardService(
        ILogger<BlockGuardService> logger,
        IOptions<BlockGuardOptions> options,
        IFileAccessMonitor monitor,
        IPolicyEvaluator policyEvaluator,
        IAclEnforcer aclEnforcer,
        IAuditLogger auditLogger,
        IDpapiWrapper dpapiWrapper)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        _policyEvaluator = policyEvaluator ?? throw new ArgumentNullException(nameof(policyEvaluator));
        _aclEnforcer = aclEnforcer ?? throw new ArgumentNullException(nameof(aclEnforcer));
        _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
        _dpapiWrapper = dpapiWrapper ?? throw new ArgumentNullException(nameof(dpapiWrapper));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "========================================\n" +
            " BlockGuard Security Agent Starting\n" +
            " Protected Paths: {PathCount}\n" +
            " Authorized Rules: {RuleCount}\n" +
            " PID: {PID}\n" +
            "========================================",
            _options.ProtectedPaths.Count,
            _options.AuthorizedProcesses.Count,
            Environment.ProcessId);

        await _auditLogger.LogOperationalEventAsync(
            "AgentStart",
            "BlockGuard security agent starting.",
            new
            {
                protectedPaths = _options.ProtectedPaths,
                authorizedRules = _options.AuthorizedProcesses.Select(r => r.RuleName).ToList(),
                pid = Environment.ProcessId
            });

        try
        {
            // Phase 1: Lock down all protected files
            await LockdownProtectedFilesAsync(stoppingToken);

            // Phase 2: Optionally encrypt files with DPAPI
            if (_options.EnableDpapiEncryption)
            {
                await EncryptProtectedFilesAsync(stoppingToken);
            }

            // Phase 3: Subscribe to file access events
            _monitor.OnFileAccess += HandleFileAccessAsync;

            // Phase 4: Start ETW monitoring
            await _monitor.StartAsync(stoppingToken);

            _logger.LogInformation("BlockGuard is now actively protecting {Count} path(s).",
                _options.ProtectedPaths.Count);

            // Phase 5: Periodic ACL integrity verification
            await RunIntegrityCheckLoopAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            _logger.LogInformation("BlockGuard received shutdown signal.");
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex,
                "BlockGuard encountered a fatal error and must stop. " +
                "Protected files remain locked down via ACLs.");

            await _auditLogger.LogOperationalEventAsync(
                "FatalError",
                $"Agent crashed: {ex.Message}",
                new { exception = ex.ToString() });

            throw; // Let the host handle the failure
        }
        finally
        {
            await _monitor.StopAsync();
            _monitor.OnFileAccess -= HandleFileAccessAsync;

            await _auditLogger.LogOperationalEventAsync(
                "AgentStop",
                "BlockGuard security agent stopped.");

            _logger.LogInformation("BlockGuard Security Agent stopped.");
        }
    }

    /// <summary>
    /// Applies deny-by-default ACLs to all configured protected paths.
    /// </summary>
    private async Task LockdownProtectedFilesAsync(CancellationToken cancellationToken)
    {
        foreach (var path in _options.ProtectedPaths)
        {
            try
            {
                var fullPath = Path.GetFullPath(path);

                if (File.Exists(fullPath))
                {
                    await _aclEnforcer.LockdownFileAsync(fullPath, cancellationToken);
                }
                else if (Directory.Exists(fullPath))
                {
                    // Lock down the directory itself (with inheritance to all children)
                    await _aclEnforcer.LockdownDirectoryAsync(fullPath, cancellationToken);
                }
                else
                {
                    _logger.LogWarning(
                        "Protected path '{Path}' does not exist. Skipping.", fullPath);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to lock down protected path '{Path}'. " +
                    "This file may remain accessible to unauthorized processes.", path);
            }
        }
    }

    /// <summary>
    /// Encrypts all protected files using DPAPI.
    /// Skips files that are already encrypted (have .enc extension).
    /// </summary>
    private async Task EncryptProtectedFilesAsync(CancellationToken cancellationToken)
    {
        foreach (var path in _options.ProtectedPaths)
        {
            try
            {
                var fullPath = Path.GetFullPath(path);

                if (File.Exists(fullPath) && !fullPath.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
                {
                    await _dpapiWrapper.EncryptFileAsync(fullPath, cancellationToken);
                }
                else if (Directory.Exists(fullPath))
                {
                    foreach (var file in Directory.EnumerateFiles(
                        fullPath, "*", SearchOption.AllDirectories))
                    {
                        if (!file.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
                        {
                            await _dpapiWrapper.EncryptFileAsync(file, cancellationToken);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to encrypt protected path '{Path}'.", path);
            }
        }
    }

    /// <summary>
    /// Handles a file access event from the ETW monitor.
    /// This is the hot path — must be fast and non-blocking.
    /// </summary>
    private async Task HandleFileAccessAsync(FileAccessEvent accessEvent)
    {
        try
        {
            // Evaluate the access against the policy
            var decision = await _policyEvaluator.EvaluateAsync(
                accessEvent, CancellationToken.None);

            // Audit the decision (never throw)
            await _auditLogger.LogAccessDecisionAsync(accessEvent, decision);

            // If denied, the ACL is already enforcing the denial.
            // If allowed and the process needs a temporary handle, grant it now.
            if (decision.Verdict == AccessVerdict.Allow &&
                decision.ProcessIdentity?.OwnerSid != null)
            {
                // Grant temporary ACL-based read access
                var grant = await _aclEnforcer.GrantTemporaryAccessAsync(
                    accessEvent.FilePath,
                    decision.ProcessIdentity.OwnerSid,
                    _options.HandleTimeoutSeconds,
                    CancellationToken.None);

                // The grant auto-revokes after the timeout.
                // We don't hold a reference — the timer handles cleanup.
                _logger.LogDebug(
                    "Temporary access granted for PID {PID} to '{File}' for {Timeout}s.",
                    accessEvent.ProcessId, accessEvent.FilePath,
                    _options.HandleTimeoutSeconds);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Error handling file access event {EventId} for '{File}' (PID: {PID}).",
                accessEvent.EventId, accessEvent.FilePath, accessEvent.ProcessId);
        }
    }

    /// <summary>
    /// Periodically verifies that ACLs on protected files haven't been tampered with.
    /// Runs every 60 seconds.
    /// </summary>
    private async Task RunIntegrityCheckLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(60));

        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            foreach (var path in _options.ProtectedPaths)
            {
                try
                {
                    var fullPath = Path.GetFullPath(path);

                    if (File.Exists(fullPath))
                    {
                        var intact = await _aclEnforcer.VerifyAclIntegrityAsync(fullPath);
                        if (!intact)
                        {
                            _logger.LogCritical(
                                "ACL TAMPERING DETECTED on '{File}'! Re-applying lockdown.",
                                fullPath);

                            await _auditLogger.LogOperationalEventAsync(
                                "AclTampering",
                                $"ACL tampering detected on '{fullPath}'. Re-applying lockdown.");

                            await _aclEnforcer.LockdownFileAsync(fullPath, cancellationToken);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex,
                        "Error during ACL integrity check for '{Path}'.", path);
                }
            }
        }
    }
}
