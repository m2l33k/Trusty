using System.Windows;

namespace BlockGuard.UI;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    // ----- Page Navigation -----

    private void ShowPage(string pageName)
    {
        DashboardPage.Visibility = Visibility.Collapsed;
        ProtectedFilesPage.Visibility = Visibility.Collapsed;
        ActivityPage.Visibility = Visibility.Collapsed;
        SettingsPage.Visibility = Visibility.Collapsed;

        switch (pageName)
        {
            case "Dashboard":
                DashboardPage.Visibility = Visibility.Visible;
                break;
            case "ProtectedFiles":
                ProtectedFilesPage.Visibility = Visibility.Visible;
                break;
            case "Activity":
                ActivityPage.Visibility = Visibility.Visible;
                break;
            case "Settings":
                SettingsPage.Visibility = Visibility.Visible;
                break;
        }
    }

    private void Nav_Dashboard(object sender, RoutedEventArgs e) => ShowPage("Dashboard");
    private void Nav_ProtectedFiles(object sender, RoutedEventArgs e) => ShowPage("ProtectedFiles");
    private void Nav_Activity(object sender, RoutedEventArgs e) => ShowPage("Activity");
    private void Nav_Settings(object sender, RoutedEventArgs e) => ShowPage("Settings");
}