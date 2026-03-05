// -----------------------------------------------------------------------
// BlockGuard.UI - ViewModels/MainViewModel.cs
// MVVM ViewModel for the main window. Manages protected paths list
// and interacts with the ConfigurationService.
// -----------------------------------------------------------------------

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using BlockGuard.UI.Services;
using Microsoft.Win32;

namespace BlockGuard.UI.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly ConfigurationService _configService;
    private readonly DispatcherTimer _statusTimer;
    private AppConfig _config = new();
    private Process? _agentProcess;
    private bool _isTogglingAgent;

    private string _statusText = "Loading...";
    private string _statusIcon = "⏳";
    private bool _isAgentRunning;
    private int _selectedNavIndex;
    private string _configFilePath = "";
    private bool _hasUnsavedChanges;
    private string _searchQuery = "";

    public MainViewModel()
    {
        _configService = new ConfigurationService();
        ProtectedItems = new ObservableCollection<ProtectedItemViewModel>();
        RecentActivityItems = new ObservableCollection<ActivityItem>();

        // Commands
        AddFileCommand = new RelayCommand(AddFile);
        AddFolderCommand = new RelayCommand(AddFolder);
        RemoveItemCommand = new RelayCommand<ProtectedItemViewModel>(RemoveItem);
        SaveCommand = new RelayCommand(SaveConfig);
        RefreshCommand = new RelayCommand(RefreshConfig);
        ToggleAgentCommand = new RelayCommand(ToggleAgent);

        // Status polling timer (check agent status every 3 seconds)
        _statusTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(3)
        };
        _statusTimer.Tick += (_, _) => CheckAgentStatus();
        _statusTimer.Start();
    }

    /// <summary>
    /// Called from code-behind after the window is loaded (safe to use Dispatcher).
    /// </summary>
    public async Task InitializeAsync()
    {
        await LoadConfigAsync();
    }

    private async void SaveConfig()
    {
        await SaveConfigAsync();
    }

    private async void RefreshConfig()
    {
        await LoadConfigAsync();
    }

    // ----- Properties -----

    public ObservableCollection<ProtectedItemViewModel> ProtectedItems { get; }
    public ObservableCollection<ActivityItem> RecentActivityItems { get; }

    public string StatusText
    {
        get => _statusText;
        set { _statusText = value; OnPropertyChanged(); }
    }

    public string StatusIcon
    {
        get => _statusIcon;
        set { _statusIcon = value; OnPropertyChanged(); }
    }

    public bool IsAgentRunning
    {
        get => _isAgentRunning;
        set { _isAgentRunning = value; OnPropertyChanged(); }
    }

    public int SelectedNavIndex
    {
        get => _selectedNavIndex;
        set { _selectedNavIndex = value; OnPropertyChanged(); }
    }

    public string ConfigFilePath
    {
        get => _configFilePath;
        set { _configFilePath = value; OnPropertyChanged(); }
    }

    public bool HasUnsavedChanges
    {
        get => _hasUnsavedChanges;
        set { _hasUnsavedChanges = value; OnPropertyChanged(); }
    }

    public string SearchQuery
    {
        get => _searchQuery;
        set { _searchQuery = value; OnPropertyChanged(); FilterItems(); }
    }

    public int TotalProtectedFiles => ProtectedItems.Count(i => i.ItemType == ProtectedItemType.File);
    public int TotalProtectedFolders => ProtectedItems.Count(i => i.ItemType == ProtectedItemType.Folder);
    public int TotalProtectedItems => ProtectedItems.Count;
    public bool EnableDpapiEncryption => _config.BlockGuard?.EnableDpapiEncryption ?? false;

    public bool IsTogglingAgent
    {
        get => _isTogglingAgent;
        set { _isTogglingAgent = value; OnPropertyChanged(); }
    }

    // ----- Commands -----

    public ICommand AddFileCommand { get; }
    public ICommand AddFolderCommand { get; }
    public ICommand RemoveItemCommand { get; }
    public ICommand SaveCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand ToggleAgentCommand { get; }

    // ----- Methods -----

    private async Task LoadConfigAsync()
    {
        try
        {
            _config = await _configService.LoadAsync();
            ConfigFilePath = _configService.ConfigPath;

            ProtectedItems.Clear();
            foreach (var path in _config.BlockGuard.ProtectedPaths)
            {
                var item = CreateProtectedItem(path);
                ProtectedItems.Add(item);
            }

            // Check if agent service is running
            CheckAgentStatus();

            HasUnsavedChanges = false;
            UpdateStats();
            AddActivity("Configuration loaded", $"Loaded {ProtectedItems.Count} protected path(s)");
        }
        catch (Exception ex)
        {
            StatusText = $"Error: {ex.Message}";
            StatusIcon = "❌";
            AddActivity("Error", ex.Message);
        }
    }

    private async Task SaveConfigAsync()
    {
        try
        {
            _config.BlockGuard.ProtectedPaths = ProtectedItems
                .Select(i => i.FullPath)
                .ToList();

            await _configService.SaveAsync(_config);

            HasUnsavedChanges = false;
            AddActivity("Configuration saved", $"Saved {ProtectedItems.Count} protected path(s)");

            MessageBox.Show(
                $"Configuration saved successfully to:\n{ConfigFilePath}\n\n" +
                "Restart the BlockGuard Agent service for changes to take effect.",
                "BlockGuard",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Failed to save configuration:\n{ex.Message}",
                "BlockGuard — Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void AddFile()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select file to protect from AI access",
            Filter = "All Files (*.*)|*.*",
            Multiselect = true,
            CheckFileExists = true
        };

        if (dialog.ShowDialog() == true)
        {
            foreach (var file in dialog.FileNames)
            {
                if (ProtectedItems.Any(i => i.FullPath.Equals(file, StringComparison.OrdinalIgnoreCase)))
                {
                    continue; // Skip duplicates
                }

                var item = CreateProtectedItem(file);
                ProtectedItems.Add(item);
                AddActivity("File added", file);
            }

            HasUnsavedChanges = true;
            UpdateStats();
        }
    }

    private void AddFolder()
    {
        // Use the folder picker via OpenFolderDialog (WPF .NET 8+)
        var dialog = new OpenFolderDialog
        {
            Title = "Select folder to protect from AI access",
            Multiselect = false
        };

        if (dialog.ShowDialog() == true)
        {
            var folder = dialog.FolderName;
            if (ProtectedItems.Any(i => i.FullPath.Equals(folder, StringComparison.OrdinalIgnoreCase)))
            {
                return; // Skip duplicate
            }

            var item = CreateProtectedItem(folder);
            ProtectedItems.Add(item);
            HasUnsavedChanges = true;
            UpdateStats();
            AddActivity("Folder added", folder);
        }
    }

    private void RemoveItem(ProtectedItemViewModel? item)
    {
        if (item == null) return;

        var result = MessageBox.Show(
            $"Remove protection from:\n{item.FullPath}\n\nThis will allow AI processes to access this path.",
            "Remove Protection",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            AddActivity("Removed", item.FullPath);
            ProtectedItems.Remove(item);
            HasUnsavedChanges = true;
            UpdateStats();
        }
    }

    private ProtectedItemViewModel CreateProtectedItem(string path)
    {
        var isDirectory = Directory.Exists(path);
        var isFile = File.Exists(path);

        string size = "";
        int fileCount = 0;

        if (isFile)
        {
            try
            {
                var fi = new FileInfo(path);
                size = FormatFileSize(fi.Length);
            }
            catch { size = "Unknown"; }
        }
        else if (isDirectory)
        {
            try
            {
                var files = Directory.GetFiles(path, "*", SearchOption.AllDirectories);
                fileCount = files.Length;
                long totalSize = files.Sum(f => new FileInfo(f).Length);
                size = FormatFileSize(totalSize);
            }
            catch { size = "Unknown"; fileCount = 0; }
        }

        return new ProtectedItemViewModel
        {
            FullPath = path,
            FileName = Path.GetFileName(path),
            DirectoryName = Path.GetDirectoryName(path) ?? "",
            ItemType = isDirectory ? ProtectedItemType.Folder : ProtectedItemType.File,
            Size = size,
            FileCount = fileCount,
            Exists = isFile || isDirectory,
            Icon = isDirectory ? "📁" : GetFileIcon(path),
            IsVisible = true
        };
    }

    private void CheckAgentStatus()
    {
        try
        {
            // Check for any running agent process (ours or externally started)
            var processes = Process.GetProcessesByName("BlockGuard.Agent");
            var wasRunning = IsAgentRunning;
            IsAgentRunning = processes.Length > 0;
            StatusText = IsAgentRunning ? "Agent Running" : "Agent Stopped";
            StatusIcon = IsAgentRunning ? "🟢" : "🔴";

            // If agent died externally, clean up our reference
            if (!IsAgentRunning && _agentProcess != null)
            {
                _agentProcess.Dispose();
                _agentProcess = null;
            }

            // Log status changes
            if (wasRunning != IsAgentRunning && wasRunning)
            {
                AddActivity("Agent stopped", "The BlockGuard Agent process has exited");
            }

            foreach (var p in processes) p.Dispose();
        }
        catch
        {
            IsAgentRunning = false;
            StatusText = "Agent Status Unknown";
            StatusIcon = "🟡";
        }
    }

    private void ToggleAgent()
    {
        if (IsAgentRunning)
        {
            StopAgent();
        }
        else
        {
            StartAgent();
        }
    }

    private void StartAgent()
    {
        try
        {
            IsTogglingAgent = true;

            // Find the agent project path and solution root
            var paths = FindAgentProjectPath();
            if (paths == null)
            {
                IsTogglingAgent = false;
                MessageBox.Show(
                    "Could not find the BlockGuard.Agent project.\n" +
                    "Make sure you are running from the solution directory.",
                    "BlockGuard",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            var (solutionDir, agentCsproj) = paths.Value;

            // Launch with elevation (UAC prompt) — required for ETW + ACL operations
            var startInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"run --project \"{agentCsproj}\"",
                UseShellExecute = true,   // Required for Verb = "runas"
                Verb = "runas",           // Triggers UAC elevation prompt
                WorkingDirectory = solutionDir
            };

            _agentProcess = Process.Start(startInfo);

            if (_agentProcess != null)
            {
                // Give the process a moment to start
                Task.Delay(2000).ContinueWith(_ =>
                {
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        CheckAgentStatus();
                        IsTogglingAgent = false;
                        AddActivity("Agent started", $"PID {_agentProcess?.Id}");
                    });
                });
            }
            else
            {
                IsTogglingAgent = false;
                AddActivity("Error", "Failed to start agent process");
            }
        }
        catch (Exception ex)
        {
            IsTogglingAgent = false;
            MessageBox.Show(
                $"Failed to start the BlockGuard Agent:\n{ex.Message}\n\n" +
                "Tip: For ETW and ACL operations, the agent must run as Administrator.",
                "BlockGuard - Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            AddActivity("Start failed", ex.Message);
        }
    }

    private void StopAgent()
    {
        try
        {
            IsTogglingAgent = true;

            // Kill our own launched process if we have one
            if (_agentProcess is { HasExited: false })
            {
                _agentProcess.Kill(entireProcessTree: true);
                _agentProcess.WaitForExit(3000);
                _agentProcess.Dispose();
                _agentProcess = null;
            }
            else
            {
                // Kill any externally started agent processes
                var processes = Process.GetProcessesByName("BlockGuard.Agent");
                foreach (var p in processes)
                {
                    try { p.Kill(); } catch { /* best effort */ }
                    p.Dispose();
                }
            }

            // Give time for process to exit
            Task.Delay(1000).ContinueWith(_ =>
            {
                Application.Current?.Dispatcher.Invoke(() =>
                {
                    CheckAgentStatus();
                    IsTogglingAgent = false;
                    AddActivity("Agent stopped", "Agent process terminated by user");
                });
            });
        }
        catch (Exception ex)
        {
            IsTogglingAgent = false;
            MessageBox.Show(
                $"Failed to stop the BlockGuard Agent:\n{ex.Message}",
                "BlockGuard - Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            AddActivity("Stop failed", ex.Message);
        }
    }

    /// <summary>
    /// Walks up the directory tree to find the solution root and Agent .csproj.
    /// Returns (solutionDir, agentCsprojPath) or null if not found.
    /// </summary>
    private static (string SolutionDir, string CsprojPath)? FindAgentProjectPath()
    {
        var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
        while (dir != null)
        {
            var slnFiles = dir.GetFiles("BlockGuard.sln");
            if (slnFiles.Length > 0)
            {
                var agentCsproj = Path.Combine(dir.FullName, "src", "BlockGuard.Agent", "BlockGuard.Agent.csproj");
                if (File.Exists(agentCsproj))
                    return (dir.FullName, agentCsproj);
            }
            dir = dir.Parent;
        }
        return null;
    }

    private void UpdateStats()
    {
        OnPropertyChanged(nameof(TotalProtectedFiles));
        OnPropertyChanged(nameof(TotalProtectedFolders));
        OnPropertyChanged(nameof(TotalProtectedItems));
        OnPropertyChanged(nameof(EnableDpapiEncryption));
    }

    private void FilterItems()
    {
        foreach (var item in ProtectedItems)
        {
            item.IsVisible = string.IsNullOrWhiteSpace(SearchQuery) ||
                             item.FullPath.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
                             item.FileName.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase);
        }
    }

    private void AddActivity(string action, string detail)
    {
        void DoAdd()
        {
            RecentActivityItems.Insert(0, new ActivityItem
            {
                Timestamp = DateTime.Now,
                Action = action,
                Detail = detail
            });

            // Keep only last 50 entries
            while (RecentActivityItems.Count > 50)
            {
                RecentActivityItems.RemoveAt(RecentActivityItems.Count - 1);
            }
        }

        var app = Application.Current;
        if (app?.Dispatcher != null && !app.Dispatcher.CheckAccess())
        {
            app.Dispatcher.Invoke(DoAdd);
        }
        else
        {
            DoAdd();
        }
    }

    private static string GetFileIcon(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext switch
        {
            ".json" => "📋",
            ".xml" => "📋",
            ".key" or ".pem" or ".crt" or ".cer" => "🔑",
            ".env" => "⚙️",
            ".db" or ".sqlite" => "🗄️",
            ".txt" or ".log" => "📄",
            ".exe" or ".dll" => "⚙️",
            ".zip" or ".7z" or ".tar" => "📦",
            _ => "📄"
        };
    }

    private static string FormatFileSize(long bytes)
    {
        string[] suffixes = ["B", "KB", "MB", "GB", "TB"];
        int counter = 0;
        decimal number = bytes;
        while (Math.Round(number / 1024) >= 1 && counter < suffixes.Length - 1)
        {
            number /= 1024;
            counter++;
        }
        return $"{number:N1} {suffixes[counter]}";
    }

    // ----- INotifyPropertyChanged -----

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

// ----- Supporting Models -----

public sealed class ProtectedItemViewModel : INotifyPropertyChanged
{
    private bool _isVisible = true;

    public required string FullPath { get; set; }
    public required string FileName { get; set; }
    public required string DirectoryName { get; set; }
    public required ProtectedItemType ItemType { get; set; }
    public required string Size { get; set; }
    public int FileCount { get; set; }
    public required bool Exists { get; set; }
    public required string Icon { get; set; }

    public bool IsVisible
    {
        get => _isVisible;
        set { _isVisible = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsVisible))); }
    }

    public string TypeLabel => ItemType == ProtectedItemType.Folder ? "Folder" : "File";
    public string StatusText => Exists ? "Protected" : "Missing";

    public event PropertyChangedEventHandler? PropertyChanged;
}

public enum ProtectedItemType { File, Folder }

public sealed class ActivityItem
{
    public required DateTime Timestamp { get; set; }
    public required string Action { get; set; }
    public required string Detail { get; set; }
    public string TimeAgo => FormatTimeAgo(Timestamp);

    private static string FormatTimeAgo(DateTime dt)
    {
        var span = DateTime.Now - dt;
        if (span.TotalSeconds < 60) return "Just now";
        if (span.TotalMinutes < 60) return $"{(int)span.TotalMinutes}m ago";
        if (span.TotalHours < 24) return $"{(int)span.TotalHours}h ago";
        return dt.ToString("MMM dd HH:mm");
    }
}

// ----- Relay Command -----

public sealed class RelayCommand : ICommand
{
    private readonly Action _execute;
    private readonly Func<bool>? _canExecute;

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke() ?? true;
    public void Execute(object? parameter) => _execute();
    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}

public sealed class RelayCommand<T> : ICommand
{
    private readonly Action<T?> _execute;
    private readonly Func<T?, bool>? _canExecute;

    public RelayCommand(Action<T?> execute, Func<T?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke((T?)parameter) ?? true;
    public void Execute(object? parameter) => _execute((T?)parameter);
    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}
