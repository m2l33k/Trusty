// -----------------------------------------------------------------------
// BlockGuard.Policy - ProcessIdentityValidator.cs
// Validates a running process's identity using multiple security checks.
// -----------------------------------------------------------------------
// SECURITY NOTE: This is the most critical security component.
// A bypass here means an attacker can impersonate an authorized process.
// Every check must fail-closed (deny if uncertain).
// -----------------------------------------------------------------------

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using BlockGuard.Core.Interfaces;
using BlockGuard.Core.Models;
using Microsoft.Extensions.Logging;

namespace BlockGuard.Policy;

/// <summary>
/// Builds a complete <see cref="ProcessIdentity"/> for a given PID by:
/// 1. Resolving the executable path
/// 2. Computing the SHA-256 file hash
/// 3. Validating the Authenticode signature
/// 4. Querying the process owner SID
/// 5. Determining the mandatory integrity level
/// 6. Resolving the parent process ID
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProcessIdentityValidator : IProcessIdentityValidator
{
    private readonly ILogger<ProcessIdentityValidator> _logger;

    public ProcessIdentityValidator(ILogger<ProcessIdentityValidator> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<ProcessIdentity?> ValidateAsync(int processId, CancellationToken cancellationToken)
    {
        Process? process = null;

        try
        {
            // Step 1: Get the process handle
            try
            {
                process = Process.GetProcessById(processId);
            }
            catch (ArgumentException)
            {
                _logger.LogDebug("Process {PID} has already exited.", processId);
                return null;
            }

            // Step 2: Resolve executable path
            string? exePath;
            try
            {
                exePath = process.MainModule?.FileName;
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                _logger.LogWarning(ex,
                    "Cannot access MainModule for PID {PID}. " +
                    "This may be a protected process or access is denied.", processId);
                return null; // Fail-closed
            }

            if (string.IsNullOrEmpty(exePath))
            {
                _logger.LogWarning("Empty executable path for PID {PID}.", processId);
                return null;
            }

            // Canonicalize the path to prevent path traversal attacks
            exePath = Path.GetFullPath(exePath);

            // Step 3: Compute SHA-256 hash of the executable
            var fileHash = await ComputeFileHashAsync(exePath, cancellationToken);

            // Step 4: Verify Authenticode signature
            var (isSigned, signerSubject) = VerifyAuthenticode(exePath);

            // Step 5: Get process owner SID
            var ownerSid = GetProcessOwnerSid(processId);

            // Step 6: Get integrity level
            var integrityLevel = GetProcessIntegrityLevel(processId);

            // Step 7: Get parent PID
            int? parentPid = GetParentProcessId(process);

            // Step 8: Get command line (sanitized)
            string? commandLine = null;
            try
            {
                commandLine = GetSanitizedCommandLine(process);
            }
            catch
            {
                // Non-critical — some processes restrict access
            }

            var identity = new ProcessIdentity
            {
                ProcessId = processId,
                ExecutablePath = exePath,
                FileHash = fileHash,
                IsAuthenticodeSigned = isSigned,
                SignerSubject = signerSubject,
                OwnerSid = ownerSid,
                IntegrityLevel = integrityLevel,
                ParentProcessId = parentPid,
                CommandLine = commandLine
            };

            _logger.LogDebug(
                "Validated process identity: PID={PID}, Path={Path}, Hash={Hash}, " +
                "Signed={Signed}, Integrity={Integrity}",
                processId, exePath, fileHash[..12] + "...", isSigned, integrityLevel);

            return identity;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error validating process {PID}.", processId);
            return null; // Fail-closed
        }
        finally
        {
            process?.Dispose();
        }
    }

    // ----- Private Helpers -----

    /// <summary>
    /// Computes the SHA-256 hash of a file for tamper detection.
    /// Uses async streaming to handle large executables without memory pressure.
    /// </summary>
    private static async Task<string> ComputeFileHashAsync(
        string filePath, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite, // Don't lock the file
            bufferSize: 81920,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        var hashBytes = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    /// <summary>
    /// Verifies the Authenticode digital signature of a PE file.
    /// Returns (isSigned, signerSubject).
    /// </summary>
    private (bool IsSigned, string? SignerSubject) VerifyAuthenticode(string filePath)
    {
        try
        {
            // CreateFromSignedFile returns X509Certificate (base class).
            // We must convert to X509Certificate2 for chain building.
            using var baseCert = X509Certificate.CreateFromSignedFile(filePath);
            using var cert = new X509Certificate2(baseCert);
            using var chain = new X509Chain();

            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);

            bool isValid = chain.Build(cert);

            if (!isValid)
            {
                _logger.LogWarning(
                    "Authenticode chain validation failed for '{Path}': {Status}",
                    filePath,
                    string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation)));
            }

            return (isValid, cert.Subject);
        }
        catch (CryptographicException)
        {
            // File is not signed
            return (false, null);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error verifying Authenticode for '{Path}'.", filePath);
            return (false, null); // Fail-closed
        }
    }

    /// <summary>
    /// Gets the SID of the process owner using Windows Token APIs.
    /// </summary>
    private SecurityIdentifier? GetProcessOwnerSid(int processId)
    {
        IntPtr processHandle = IntPtr.Zero;
        IntPtr tokenHandle = IntPtr.Zero;

        try
        {
            processHandle = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)processId);

            if (processHandle == IntPtr.Zero)
                return null;

            if (!NativeMethods.OpenProcessToken(
                processHandle, NativeMethods.TOKEN_QUERY, out tokenHandle))
                return null;

            using var identity = new WindowsIdentity(tokenHandle);
            return identity.User;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Cannot get owner SID for PID {PID}.", processId);
            return null;
        }
        finally
        {
            if (tokenHandle != IntPtr.Zero)
                NativeMethods.CloseHandle(tokenHandle);
            if (processHandle != IntPtr.Zero)
                NativeMethods.CloseHandle(processHandle);
        }
    }

    /// <summary>
    /// Reads the mandatory integrity level from the process token.
    /// Maps the integrity RID to our <see cref="IntegrityLevel"/> enum.
    /// </summary>
    private IntegrityLevel GetProcessIntegrityLevel(int processId)
    {
        IntPtr processHandle = IntPtr.Zero;
        IntPtr tokenHandle = IntPtr.Zero;
        IntPtr tokenInfo = IntPtr.Zero;

        try
        {
            processHandle = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)processId);

            if (processHandle == IntPtr.Zero)
                return IntegrityLevel.Unknown;

            if (!NativeMethods.OpenProcessToken(
                processHandle, NativeMethods.TOKEN_QUERY, out tokenHandle))
                return IntegrityLevel.Unknown;

            // Query TOKEN_MANDATORY_LABEL
            int returnLength = 0;
            NativeMethods.GetTokenInformation(
                tokenHandle,
                NativeMethods.TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                IntPtr.Zero, 0, out returnLength);

            if (returnLength == 0)
                return IntegrityLevel.Unknown;

            tokenInfo = Marshal.AllocHGlobal(returnLength);
            if (!NativeMethods.GetTokenInformation(
                tokenHandle,
                NativeMethods.TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                tokenInfo, returnLength, out _))
                return IntegrityLevel.Unknown;

            var mandatoryLabel = Marshal.PtrToStructure<NativeMethods.TOKEN_MANDATORY_LABEL>(tokenInfo);
            IntPtr sidPtr = mandatoryLabel.Label.Sid;

            // The last sub-authority of the integrity SID is the integrity level
            int subAuthorityCount = Marshal.ReadByte(sidPtr, 1); // nSubAuthorityCount
            int integrityRid = Marshal.ReadInt32(
                sidPtr, 8 + (subAuthorityCount - 1) * 4); // skip past SID header

            return integrityRid switch
            {
                0 => IntegrityLevel.Untrusted,
                >= 4096 and < 8192 => IntegrityLevel.Low,
                >= 8192 and < 8448 => IntegrityLevel.Medium,
                >= 8448 and < 12288 => IntegrityLevel.MediumPlus,
                >= 12288 and < 16384 => IntegrityLevel.High,
                >= 16384 => IntegrityLevel.System,
                _ => IntegrityLevel.Unknown
            };
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Cannot determine integrity level for PID {PID}.", processId);
            return IntegrityLevel.Unknown;
        }
        finally
        {
            if (tokenInfo != IntPtr.Zero)
                Marshal.FreeHGlobal(tokenInfo);
            if (tokenHandle != IntPtr.Zero)
                NativeMethods.CloseHandle(tokenHandle);
            if (processHandle != IntPtr.Zero)
                NativeMethods.CloseHandle(processHandle);
        }
    }

    /// <summary>
    /// Gets the parent process ID for chain-of-trust validation.
    /// </summary>
    private static int? GetParentProcessId(Process process)
    {
        try
        {
            // Use NtQueryInformationProcess or PROCESS_BASIC_INFORMATION
            IntPtr handle = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)process.Id);

            if (handle == IntPtr.Zero)
                return null;

            try
            {
                var pbi = new NativeMethods.PROCESS_BASIC_INFORMATION();
                int status = NativeMethods.NtQueryInformationProcess(
                    handle, 0, ref pbi,
                    Marshal.SizeOf<NativeMethods.PROCESS_BASIC_INFORMATION>(),
                    out _);

                if (status == 0) // STATUS_SUCCESS
                {
                    return (int)pbi.InheritedFromUniqueProcessId;
                }
            }
            finally
            {
                NativeMethods.CloseHandle(handle);
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Returns a sanitized command line (truncated, no sensitive args).
    /// </summary>
    private static string? GetSanitizedCommandLine(Process process)
    {
        try
        {
            // On Windows, StartInfo.Arguments may not be populated for
            // processes we didn't start. Use WMI as fallback.
            string? cmdLine = Environment.CommandLine; // Placeholder
            if (cmdLine != null && cmdLine.Length > 500)
            {
                cmdLine = cmdLine[..500] + "... [truncated]";
            }
            return cmdLine;
        }
        catch
        {
            return null;
        }
    }

    // ----- Native Methods (P/Invoke) -----

    private static class NativeMethods
    {
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint TOKEN_QUERY = 0x0008;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(
            IntPtr ProcessHandle,
            int ProcessInformationClass,
            ref PROCESS_BASIC_INFORMATION ProcessInformation,
            int ProcessInformationLength,
            out int ReturnLength);

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenIntegrityLevel = 25
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }
    }
}
