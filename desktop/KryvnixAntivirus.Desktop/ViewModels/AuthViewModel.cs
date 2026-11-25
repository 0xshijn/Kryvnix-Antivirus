using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KryvnixAntivirus.Desktop.Services;

namespace KryvnixAntivirus.Desktop.ViewModels;

public enum AuthDialogMode
{
    Register,
    Login,
    ChangePassword
}

public partial class AuthViewModel : ObservableObject
{
    private readonly IAuthService _authService;
    private readonly IAppStateService _appState;

    [ObservableProperty] private bool _isOpen;
    [ObservableProperty] private AuthDialogMode _mode = AuthDialogMode.Register;

    // Register fields
    [ObservableProperty] private string _fullName = string.Empty;
    [ObservableProperty] private string _username = string.Empty;
    [ObservableProperty] private string _email = string.Empty;
    [ObservableProperty] private string _password = string.Empty;
    [ObservableProperty] private string _confirmPassword = string.Empty;

    // Login fields
    [ObservableProperty] private string _loginIdentifier = string.Empty;
    [ObservableProperty] private string _loginPassword = string.Empty;

    // Change Password fields
    [ObservableProperty] private string _currentPassword = string.Empty;
    [ObservableProperty] private string _newPassword = string.Empty;
    [ObservableProperty] private string _confirmNewPassword = string.Empty;

    [ObservableProperty] private bool _rememberSession = true;
    [ObservableProperty] private bool _showPassword;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _errorMessage = string.Empty;
    [ObservableProperty] private string _successMessage = string.Empty;

    [ObservableProperty] private int _passwordStrengthLevel;
    [ObservableProperty] private string _passwordStrengthLabel = "Tối thiểu 8 ký tự gồm chữ và số";
    [ObservableProperty] private string _passwordStrengthColorHex = "#64748B";

    public bool IsRegisterMode => Mode == AuthDialogMode.Register;
    public bool IsLoginMode => Mode == AuthDialogMode.Login;
    public bool IsChangePasswordMode => Mode == AuthDialogMode.ChangePassword;
    public bool HasError => !string.IsNullOrWhiteSpace(ErrorMessage);
    public bool HasSuccess => !string.IsNullOrWhiteSpace(SuccessMessage);
    public bool StrengthBar1Active => PasswordStrengthLevel >= 1;
    public bool StrengthBar2Active => PasswordStrengthLevel >= 2;
    public bool StrengthBar3Active => PasswordStrengthLevel >= 3;
    public bool StrengthBar4Active => PasswordStrengthLevel >= 4;

    public string ModalTitle => Mode switch
    {
        AuthDialogMode.Register => "Đăng ký tài khoản Kryvnix",
        AuthDialogMode.Login => "Đăng nhập Kryvnix Antivirus",
        _ => "Đổi mật khẩu tài khoản"
    };

    public string ModalSubtitle => Mode switch
    {
        AuthDialogMode.Register => "Tạo tài khoản bảo mật để đồng bộ thiết bị và bảo vệ cài đặt",
        AuthDialogMode.Login => "Đăng nhập bằng tên tài khoản hoặc địa chỉ email của bạn",
        _ => "Cập nhật mật khẩu mới được mã hóa an toàn bằng PBKDF2-SHA256"
    };

    public AuthViewModel(IAuthService authService, IAppStateService appState)
    {
        _authService = authService;
        _appState = appState;
    }

    partial void OnModeChanged(AuthDialogMode value)
    {
        ErrorMessage = string.Empty;
        SuccessMessage = string.Empty;
        OnPropertyChanged(nameof(IsRegisterMode));
        OnPropertyChanged(nameof(IsLoginMode));
        OnPropertyChanged(nameof(IsChangePasswordMode));
        OnPropertyChanged(nameof(ModalTitle));
        OnPropertyChanged(nameof(ModalSubtitle));
        UpdateStrengthMeter(value == AuthDialogMode.ChangePassword ? NewPassword : Password);
    }

    partial void OnErrorMessageChanged(string value) => OnPropertyChanged(nameof(HasError));
    partial void OnSuccessMessageChanged(string value) => OnPropertyChanged(nameof(HasSuccess));

    partial void OnPasswordChanged(string value)
    {
        if (Mode == AuthDialogMode.Register) UpdateStrengthMeter(value);
    }

    partial void OnNewPasswordChanged(string value)
    {
        if (Mode == AuthDialogMode.ChangePassword) UpdateStrengthMeter(value);
    }

    partial void OnPasswordStrengthLevelChanged(int value)
    {
        OnPropertyChanged(nameof(StrengthBar1Active));
        OnPropertyChanged(nameof(StrengthBar2Active));
        OnPropertyChanged(nameof(StrengthBar3Active));
        OnPropertyChanged(nameof(StrengthBar4Active));
    }

    private void UpdateStrengthMeter(string pwd)
    {
        if (string.IsNullOrEmpty(pwd))
        {
            PasswordStrengthLevel = 0;
            PasswordStrengthLabel = "Tối thiểu 8 ký tự gồm chữ và số";
            PasswordStrengthColorHex = "#64748B";
            return;
        }

        var (level, label, hex) = _authService.EvaluatePasswordStrength(pwd);
        PasswordStrengthLevel = level;
        PasswordStrengthLabel = $"Độ mạnh mật khẩu: {label}";
        PasswordStrengthColorHex = hex;
    }

    public void Open(AuthDialogMode initialMode)
    {
        ClearSensitiveFields();
        Mode = initialMode;
        ErrorMessage = string.Empty;
        SuccessMessage = string.Empty;
        IsOpen = true;
    }

    [RelayCommand]
    private void Close()
    {
        ClearSensitiveFields();
        IsOpen = false;
    }

    [RelayCommand]
    private void SwitchToRegister() => Mode = AuthDialogMode.Register;

    [RelayCommand]
    private void SwitchToLogin() => Mode = AuthDialogMode.Login;

    [RelayCommand]
    private void ToggleShowPassword() => ShowPassword = !ShowPassword;

    [RelayCommand]
    private async Task SubmitRegisterAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        ErrorMessage = string.Empty;
        SuccessMessage = string.Empty;

        try
        {
            var result = await _authService.RegisterAsync(FullName, Username, Email, Password, ConfirmPassword, RememberSession);
            if (!result.Success)
            {
                ErrorMessage = result.Message;
                return;
            }

            SuccessMessage = result.Message;
            await _appState.RefreshGlobalStateAsync();
            await Task.Delay(750);
            Close();
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task SubmitLoginAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        ErrorMessage = string.Empty;
        SuccessMessage = string.Empty;

        try
        {
            var result = await _authService.LoginAsync(LoginIdentifier, LoginPassword, RememberSession);
            if (!result.Success)
            {
                ErrorMessage = result.Message;
                return;
            }

            SuccessMessage = result.Message;
            await _appState.RefreshGlobalStateAsync();
            await Task.Delay(600);
            Close();
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task SubmitChangePasswordAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        ErrorMessage = string.Empty;
        SuccessMessage = string.Empty;

        try
        {
            var result = await _authService.ChangePasswordAsync(CurrentPassword, NewPassword, ConfirmNewPassword);
            if (!result.Success)
            {
                ErrorMessage = result.Message;
                return;
            }

            SuccessMessage = result.Message;
            await _appState.RefreshGlobalStateAsync();
            await Task.Delay(750);
            Close();
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ClearSensitiveFields()
    {
        Password = string.Empty;
        ConfirmPassword = string.Empty;
        LoginPassword = string.Empty;
        CurrentPassword = string.Empty;
        NewPassword = string.Empty;
        ConfirmNewPassword = string.Empty;
        ShowPassword = false;
        UpdateStrengthMeter(string.Empty);
    }
}
