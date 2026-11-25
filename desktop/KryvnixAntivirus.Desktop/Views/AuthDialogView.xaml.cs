using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using KryvnixAntivirus.Desktop.ViewModels;

namespace KryvnixAntivirus.Desktop.Views;

public partial class AuthDialogView : UserControl
{
    private bool _syncing;

    public AuthDialogView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is INotifyPropertyChanged oldNpc)
        {
            oldNpc.PropertyChanged -= OnVmPropertyChanged;
        }
        if (e.NewValue is INotifyPropertyChanged newNpc)
        {
            newNpc.PropertyChanged += OnVmPropertyChanged;
        }
    }

    private void OnVmPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (DataContext is not AuthViewModel vm) return;
        if (e.PropertyName is nameof(AuthViewModel.IsOpen) or nameof(AuthViewModel.Mode) or nameof(AuthViewModel.ShowPassword))
        {
            SyncBoxesFromViewModel(vm);
        }
    }

    private void SyncBoxesFromViewModel(AuthViewModel vm)
    {
        _syncing = true;
        try
        {
            if (RegPasswordBox.Password != vm.Password) RegPasswordBox.Password = vm.Password;
            if (RegConfirmPasswordBox.Password != vm.ConfirmPassword) RegConfirmPasswordBox.Password = vm.ConfirmPassword;
            if (LoginPasswordBox.Password != vm.LoginPassword) LoginPasswordBox.Password = vm.LoginPassword;
            if (CurrentPasswordBox.Password != vm.CurrentPassword) CurrentPasswordBox.Password = vm.CurrentPassword;
            if (NewPasswordBox.Password != vm.NewPassword) NewPasswordBox.Password = vm.NewPassword;
            if (ConfirmNewPasswordBox.Password != vm.ConfirmNewPassword) ConfirmNewPasswordBox.Password = vm.ConfirmNewPassword;
        }
        finally
        {
            _syncing = false;
        }
    }

    private void RegPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing && DataContext is AuthViewModel vm) vm.Password = RegPasswordBox.Password;
    }

    private void RegConfirmPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing && DataContext is AuthViewModel vm) vm.ConfirmPassword = RegConfirmPasswordBox.Password;
    }

    private void LoginPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing && DataContext is AuthViewModel vm) vm.LoginPassword = LoginPasswordBox.Password;
    }

    private void CurrentPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing && DataContext is AuthViewModel vm) vm.CurrentPassword = CurrentPasswordBox.Password;
    }

    private void NewPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing && DataContext is AuthViewModel vm) vm.NewPassword = NewPasswordBox.Password;
    }

    private void ConfirmNewPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (!_syncing && DataContext is AuthViewModel vm) vm.ConfirmNewPassword = ConfirmNewPasswordBox.Password;
    }
}
