// -----------------------------------------------------------------------
// BlockGuard.Core - Interfaces/IAclEnforcer.cs
// Contract for managing file ACLs as the hard enforcement layer.
// -----------------------------------------------------------------------

namespace BlockGuard.Core.Interfaces;

/// <summary>
/// Manages NTFS Access Control Lists on protected files.
/// This is the primary enforcement mechanism — ACLs are enforced by the
/// kernel regardless of user-mode monitoring state.
/// </summary>
public interface IAclEnforcer
{
    /// <summary>
    /// Locks down a file by denying read access to Everyone
    /// and only allowing SYSTEM (the agent's service account).
    /// </summary>
    /// <param name="filePath">Canonical path to the file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task LockdownFileAsync(string filePath, CancellationToken cancellationToken);

    /// <summary>
    /// Locks down a directory and all its children by denying access to Everyone
    /// and only allowing SYSTEM. Uses inherited ACLs for the directory tree.
    /// </summary>
    /// <param name="directoryPath">Canonical path to the directory.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task LockdownDirectoryAsync(string directoryPath, CancellationToken cancellationToken);

    /// <summary>
    /// Temporarily grants read access to a specific SID for a protected file.
    /// Access is revoked after the configured timeout.
    /// </summary>
    /// <param name="filePath">Canonical path to the file.</param>
    /// <param name="sid">SID to grant temporary read access to.</param>
    /// <param name="durationSeconds">How long the access remains active.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A disposable that revokes access when disposed.</returns>
    Task<IAsyncDisposable> GrantTemporaryAccessAsync(
        string filePath,
        System.Security.Principal.SecurityIdentifier sid,
        int durationSeconds,
        CancellationToken cancellationToken);

    /// <summary>
    /// Verifies that a file's ACL is still in the expected locked-down state.
    /// Call periodically to detect tampering.
    /// </summary>
    /// <param name="filePath">Canonical path to the file.</param>
    /// <returns>True if the ACL is intact, false if it has been modified.</returns>
    Task<bool> VerifyAclIntegrityAsync(string filePath);
}
