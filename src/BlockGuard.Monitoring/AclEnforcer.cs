// -----------------------------------------------------------------------
// BlockGuard.Monitoring - AclEnforcer.cs
// NTFS ACL management for hard enforcement of file access policies.
// -----------------------------------------------------------------------
// SECURITY NOTE: This is the HARD enforcement layer. Even if the ETW
// monitoring is bypassed or the agent crashes, the OS-level ACLs will
// continue to deny unauthorized access. This is defense-in-depth.
// -----------------------------------------------------------------------

using System.Security.AccessControl;
using System.Security.Principal;
using BlockGuard.Core.Configuration;
using BlockGuard.Core.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BlockGuard.Monitoring;

/// <summary>
/// Manages NTFS ACLs on protected files to enforce deny-by-default access.
/// The agent locks down files at startup and only grants temporary access
/// when the policy engine authorizes a specific process.
/// </summary>
public sealed class AclEnforcer : IAclEnforcer
{
    private readonly ILogger<AclEnforcer> _logger;
    private readonly BlockGuardOptions _options;

    // Track granted ACL entries so we can revoke them
    private readonly object _lockObj = new();

    public AclEnforcer(
        ILogger<AclEnforcer> logger,
        IOptions<BlockGuardOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc />
    public Task LockdownFileAsync(string filePath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        try
        {
            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists)
            {
                _logger.LogWarning("Cannot lock down non-existent file: {FilePath}", filePath);
                return Task.CompletedTask;
            }

            var acl = fileInfo.GetAccessControl();

            // Disable inheritance and remove all inherited rules.
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            // Remove ALL existing access rules
            var existingRules = acl.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier));

            foreach (FileSystemAccessRule rule in existingRules)
            {
                acl.RemoveAccessRule(rule);
            }

            // Implicit Deny: We remove all inherited rules and allow ONLY SYSTEM.
            // Any other process without an explicit temporary Allow rule will get Access Denied.
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            acl.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            // Note: We DO NOT call SetOwner here. Modifying ownership requires SeTakeOwnershipPrivilege
            // which often fails. Modifying the DACL to remove all `Allow` rules is sufficient.

            fileInfo.SetAccessControl(acl);

            _logger.LogInformation(
                "Locked down file '{FilePath}': Everyone DENIED, only SYSTEM allowed.",
                filePath);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogCritical(ex,
                "Cannot modify ACL on '{FilePath}' — agent lacks required privileges. " +
                "Ensure the agent runs as NT AUTHORITY\\SYSTEM.", filePath);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to lock down file '{FilePath}'.", filePath);
            throw;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Locks down a directory by setting deny ACLs on the directory itself
    /// and all files within it recursively.
    /// </summary>
    public Task LockdownDirectoryAsync(string directoryPath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);

        try
        {
            var dirInfo = new DirectoryInfo(directoryPath);
            if (!dirInfo.Exists)
            {
                _logger.LogWarning("Cannot lock down non-existent directory: {DirPath}", directoryPath);
                return Task.CompletedTask;
            }

            // Lock down the directory itself
            var acl = dirInfo.GetAccessControl();

            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            // Remove all existing rules
            var existingRules = acl.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in existingRules)
            {
                acl.RemoveAccessRule(rule);
            }

            // Implicit Deny: Allow SYSTEM full control (inherited to children)
            // Since inheritance is broken and other rules are removed, everyone else is implicitly denied.
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            acl.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            dirInfo.SetAccessControl(acl);

            _logger.LogInformation(
                "Locked down directory '{DirPath}': Everyone DENIED, only SYSTEM allowed.",
                directoryPath);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogCritical(ex,
                "Cannot modify ACL on directory '{DirPath}' — insufficient privileges.",
                directoryPath);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to lock down directory '{DirPath}'.", directoryPath);
            throw;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task<IAsyncDisposable> GrantTemporaryAccessAsync(
        string filePath,
        SecurityIdentifier sid,
        int durationSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentNullException.ThrowIfNull(sid);

        if (durationSeconds <= 0 || durationSeconds > 300)
        {
            throw new ArgumentOutOfRangeException(nameof(durationSeconds),
                "Handle timeout must be between 1 and 300 seconds.");
        }

        var fileInfo = new FileInfo(filePath);
        if (!fileInfo.Exists)
        {
            throw new FileNotFoundException("Protected file not found.", filePath);
        }

        // Add read-only access for the specified SID
        var acl = fileInfo.GetAccessControl();
        var readRule = new FileSystemAccessRule(
            sid,
            FileSystemRights.Read | FileSystemRights.Synchronize,
            AccessControlType.Allow);

        acl.AddAccessRule(readRule);
        fileInfo.SetAccessControl(acl);

        _logger.LogInformation(
            "Granted temporary READ access on '{FilePath}' to SID {Sid} for {Duration}s.",
            filePath, sid.Value, durationSeconds);

        // Return a disposable that automatically revokes access
        return new TemporaryAccessGrant(
            filePath, sid, readRule, durationSeconds, _logger, cancellationToken);
    }

    /// <inheritdoc />
    public Task<bool> VerifyAclIntegrityAsync(string filePath)
    {
        try
        {
            FileSystemSecurity acl;

            if (File.Exists(filePath))
            {
                var fileInfo = new FileInfo(filePath);
                acl = fileInfo.GetAccessControl();
            }
            else if (Directory.Exists(filePath))
            {
                var dirInfo = new DirectoryInfo(filePath);
                acl = dirInfo.GetAccessControl();
            }
            else
            {
                // Path no longer exists
                return Task.FromResult(false);
            }

            var rules = acl.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier));

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            bool hasAllowSystem = false;

            foreach (FileSystemAccessRule rule in rules)
            {
                var ruleSid = (SecurityIdentifier)rule.IdentityReference;

                if (rule.AccessControlType == AccessControlType.Allow && ruleSid.Equals(systemSid))
                {
                    hasAllowSystem = true;
                }
                else if (rule.AccessControlType == AccessControlType.Allow && !ruleSid.Equals(systemSid))
                {
                    // Unexpected allow rule (not SYSTEM)
                    // Temporary rules might exist, but log a warning just in case.
                    _logger.LogWarning(
                        "ACL integrity violation on '{FilePath}': unexpected ALLOW rule for SID {Sid}.",
                        filePath, ruleSid.Value);
                    return Task.FromResult(false);
                }
            }

            if (!hasAllowSystem)
            {
                _logger.LogWarning(
                    "ACL integrity violation on '{FilePath}': missing ALLOW rule for SYSTEM.",
                    filePath);
                return Task.FromResult(false);
            }

            // Verify inheritance is disabled (protected)
            if (!acl.AreAccessRulesProtected)
            {
                _logger.LogWarning(
                    "ACL integrity violation on '{FilePath}': inheritance is enabled (should be disabled).",
                    filePath);
                return Task.FromResult(false);
            }

            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying ACL integrity for '{FilePath}'.", filePath);
            return Task.FromResult(false);
        }
    }

    // ----- Inner class: auto-revoking temporary access -----

    /// <summary>
    /// Represents a temporary ACL grant that is automatically revoked
    /// when disposed or when the timeout expires, whichever comes first.
    /// </summary>
    private sealed class TemporaryAccessGrant : IAsyncDisposable
    {
        private readonly string _filePath;
        private readonly SecurityIdentifier _sid;
        private readonly FileSystemAccessRule _rule;
        private readonly ILogger _logger;
        private readonly CancellationTokenSource _timeoutCts;
        private readonly Task _timeoutTask;
        private int _revoked; // 0 = not revoked, 1 = revoked (interlocked)

        public TemporaryAccessGrant(
            string filePath,
            SecurityIdentifier sid,
            FileSystemAccessRule rule,
            int durationSeconds,
            ILogger logger,
            CancellationToken externalToken)
        {
            _filePath = filePath;
            _sid = sid;
            _rule = rule;
            _logger = logger;
            _timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);

            // Auto-revoke after timeout
            _timeoutTask = Task.Delay(
                TimeSpan.FromSeconds(durationSeconds), _timeoutCts.Token)
                .ContinueWith(async _ => await RevokeAsync(), TaskScheduler.Default);
        }

        public async ValueTask DisposeAsync()
        {
            await _timeoutCts.CancelAsync();
            await RevokeAsync();
            _timeoutCts.Dispose();
        }

        private Task RevokeAsync()
        {
            // Ensure we only revoke once (thread-safe)
            if (Interlocked.CompareExchange(ref _revoked, 1, 0) != 0)
                return Task.CompletedTask;

            try
            {
                var fileInfo = new FileInfo(_filePath);
                if (fileInfo.Exists)
                {
                    var acl = fileInfo.GetAccessControl();
                    acl.RemoveAccessRule(_rule);
                    fileInfo.SetAccessControl(acl);

                    _logger.LogInformation(
                        "Revoked temporary READ access on '{FilePath}' for SID {Sid}.",
                        _filePath, _sid.Value);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "CRITICAL: Failed to revoke temporary access on '{FilePath}' for SID {Sid}. " +
                    "Manual ACL cleanup may be required.", _filePath, _sid.Value);
            }

            return Task.CompletedTask;
        }
    }
}
