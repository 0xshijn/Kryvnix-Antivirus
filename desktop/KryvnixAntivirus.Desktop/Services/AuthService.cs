using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using KryvnixAntivirus.Desktop.Data;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Services;

public interface IAuthService
{
    UserAccount? CurrentUser { get; }
    bool IsAuthenticated { get; }
    event EventHandler<UserAccount?>? CurrentUserChanged;

    Task InitializeAsync(CancellationToken ct = default);
    Task<AuthResult> RegisterAsync(string fullName, string username, string email, string password, string confirmPassword, bool rememberSession = true, CancellationToken ct = default);
    Task<AuthResult> LoginAsync(string usernameOrEmail, string password, bool rememberSession = true, CancellationToken ct = default);
    Task<AuthResult> ChangePasswordAsync(string currentPassword, string newPassword, string confirmNewPassword, CancellationToken ct = default);
    Task LogoutAsync(CancellationToken ct = default);
    (int Level, string Label, string ColorHex) EvaluatePasswordStrength(string password);
}

public sealed partial class AuthService : IAuthService
{
    private const int Pbkdf2Iterations = 120_000;
    private const int SaltSizeBytes = 16;
    private const int HashSizeBytes = 32;

    private readonly ILocalDatabaseService _db;

    public UserAccount? CurrentUser { get; private set; }
    public bool IsAuthenticated => CurrentUser is not null;

    public event EventHandler<UserAccount?>? CurrentUserChanged;

    public AuthService(ILocalDatabaseService db)
    {
        _db = db;
    }

    [GeneratedRegex(@"^[a-zA-Z0-9._-]{3,32}$")]
    private static partial Regex UsernameRegex();

    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
    private static partial Regex EmailRegex();

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        var savedUserId = await _db.GetActiveSessionUserIdAsync(ct);
        if (!string.IsNullOrWhiteSpace(savedUserId))
        {
            CurrentUser = await _db.GetUserByIdAsync(savedUserId, ct);
            CurrentUserChanged?.Invoke(this, CurrentUser);
        }
    }

    public async Task<AuthResult> RegisterAsync(
        string fullName,
        string username,
        string email,
        string password,
        string confirmPassword,
        bool rememberSession = true,
        CancellationToken ct = default)
    {
        fullName = fullName?.Trim() ?? string.Empty;
        username = username?.Trim() ?? string.Empty;
        email = email?.Trim().ToLowerInvariant() ?? string.Empty;

        if (fullName.Length < 2)
        {
            return AuthResult.Fail("Họ và tên phải có ít nhất 2 ký tự.");
        }

        if (!UsernameRegex().IsMatch(username))
        {
            return AuthResult.Fail("Tên đăng nhập dài 3–32 ký tự, chỉ gồm chữ, số và dấu (., _, -).");
        }

        if (!EmailRegex().IsMatch(email))
        {
            return AuthResult.Fail("Địa chỉ email không đúng định dạng.");
        }

        var passwordError = ValidatePasswordRules(password, confirmPassword);
        if (passwordError is not null)
        {
            return AuthResult.Fail(passwordError);
        }

        if (await _db.UsernameOrEmailExistsAsync(username, email, ct))
        {
            return AuthResult.Fail("Tên đăng nhập hoặc email này đã được đăng ký trước đó.");
        }

        var now = DateTime.Now;
        var user = new UserAccount
        {
            Id = Guid.NewGuid().ToString("N"),
            FullName = fullName,
            Username = username,
            Email = email,
            PasswordHash = HashPassword(password),
            Role = "Standard",
            CreatedAt = now,
            LastLoginAt = now
        };

        await _db.CreateUserAsync(user, ct);
        CurrentUser = user;

        if (rememberSession)
        {
            await _db.SetActiveSessionUserIdAsync(user.Id, ct);
        }

        await _db.AddActivityEventAsync(new Models.ActivityEvent
        {
            EventType = ActivityEventType.SystemInfo,
            Title = "Đăng ký tài khoản thành công",
            Description = $"Tài khoản {user.FullName} (@{user.Username}) đã được khởi tạo và bảo vệ bằng PBKDF2-SHA256",
            Severity = ThreatSeverity.Low,
            IsRead = false,
            CreatedAt = now
        }, ct);

        await _db.EnqueueSyncPayloadAsync("/auth/register", JsonSerializer.Serialize(new
        {
            userId = user.Id,
            username = user.Username,
            email = user.Email,
            fullName = user.FullName,
            role = user.Role,
            createdAt = user.CreatedAt
        }), ct);

        CurrentUserChanged?.Invoke(this, CurrentUser);
        return AuthResult.Ok(user, $"Chào mừng {user.FullName}! Tài khoản đã được đăng ký thành công.");
    }

    public async Task<AuthResult> LoginAsync(
        string usernameOrEmail,
        string password,
        bool rememberSession = true,
        CancellationToken ct = default)
    {
        usernameOrEmail = usernameOrEmail?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(usernameOrEmail) || string.IsNullOrEmpty(password))
        {
            return AuthResult.Fail("Vui lòng nhập đầy đủ tên đăng nhập/email và mật khẩu.");
        }

        var user = await _db.GetUserByUsernameOrEmailAsync(usernameOrEmail, ct);
        if (user is null || !VerifyPassword(password, user.PasswordHash))
        {
            return AuthResult.Fail("Tên đăng nhập/email hoặc mật khẩu không chính xác.");
        }

        var now = DateTime.Now;
        user.LastLoginAt = now;
        await _db.UpdateUserLastLoginAsync(user.Id, now, ct);

        CurrentUser = user;
        await _db.SetActiveSessionUserIdAsync(rememberSession ? user.Id : null, ct);

        await _db.AddActivityEventAsync(new Models.ActivityEvent
        {
            EventType = ActivityEventType.SystemInfo,
            Title = "Đăng nhập tài khoản",
            Description = $"{user.FullName} (@{user.Username}) đã đăng nhập vào Kryvnix Antivirus",
            Severity = ThreatSeverity.Low,
            IsRead = true,
            CreatedAt = now
        }, ct);

        CurrentUserChanged?.Invoke(this, CurrentUser);
        return AuthResult.Ok(user, $"Đăng nhập thành công. Xin chào {user.FullName}!");
    }

    public async Task<AuthResult> ChangePasswordAsync(
        string currentPassword,
        string newPassword,
        string confirmNewPassword,
        CancellationToken ct = default)
    {
        if (CurrentUser is null)
        {
            return AuthResult.Fail("Bạn cần đăng nhập để đổi mật khẩu.");
        }

        if (!VerifyPassword(currentPassword ?? string.Empty, CurrentUser.PasswordHash))
        {
            return AuthResult.Fail("Mật khẩu hiện tại không đúng.");
        }

        var passwordError = ValidatePasswordRules(newPassword, confirmNewPassword);
        if (passwordError is not null)
        {
            return AuthResult.Fail(passwordError);
        }

        var newHash = HashPassword(newPassword);
        await _db.UpdateUserPasswordHashAsync(CurrentUser.Id, newHash, ct);
        CurrentUser.PasswordHash = newHash;

        await _db.AddActivityEventAsync(new Models.ActivityEvent
        {
            EventType = ActivityEventType.ProtectionChanged,
            Title = "Đã đổi mật khẩu tài khoản",
            Description = $"Mật khẩu của @{CurrentUser.Username} vừa được cập nhật an toàn",
            Severity = ThreatSeverity.Low,
            IsRead = false,
            CreatedAt = DateTime.Now
        }, ct);

        return AuthResult.Ok(CurrentUser, "Đổi mật khẩu thành công.");
    }

    public async Task LogoutAsync(CancellationToken ct = default)
    {
        var previous = CurrentUser;
        CurrentUser = null;
        await _db.SetActiveSessionUserIdAsync(null, ct);

        if (previous is not null)
        {
            await _db.AddActivityEventAsync(new Models.ActivityEvent
            {
                EventType = ActivityEventType.SystemInfo,
                Title = "Đăng xuất tài khoản",
                Description = $"Tài khoản @{previous.Username} đã đăng xuất khỏi phiên làm việc",
                Severity = ThreatSeverity.Low,
                IsRead = true,
                CreatedAt = DateTime.Now
            }, ct);
        }

        CurrentUserChanged?.Invoke(this, null);
    }

    public (int Level, string Label, string ColorHex) EvaluatePasswordStrength(string password)
    {
        if (string.IsNullOrEmpty(password)) return (0, "Chưa nhập mật khẩu", "#64748B");

        int score = 0;
        if (password.Length >= 8) score++;
        if (password.Length >= 12) score++;
        if (password.Any(char.IsUpper) && password.Any(char.IsLower)) score++;
        if (password.Any(char.IsDigit)) score++;
        if (password.Any(c => !char.IsLetterOrDigit(c))) score++;

        return score switch
        {
            <= 1 => (1, "Yếu", "#EF4444"),
            2 => (2, "Trung bình", "#F59E0B"),
            3 => (3, "Mạnh", "#38BDF8"),
            _ => (4, "Rất mạnh", "#22C55E")
        };
    }

    private static string? ValidatePasswordRules(string? password, string? confirmPassword)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 8)
        {
            return "Mật khẩu phải có tối thiểu 8 ký tự.";
        }

        if (!password.Any(char.IsLetter) || !password.Any(char.IsDigit))
        {
            return "Mật khẩu phải bao gồm cả chữ cái và chữ số.";
        }

        if (!string.Equals(password, confirmPassword, StringComparison.Ordinal))
        {
            return "Mật khẩu xác nhận không khớp.";
        }

        return null;
    }

    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, HashSizeBytes);
        return $"PBKDF2-SHA256${Pbkdf2Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool VerifyPassword(string password, string storedHash)
    {
        var parts = storedHash.Split('$');
        if (parts.Length != 4 || parts[0] != "PBKDF2-SHA256") return false;
        if (!int.TryParse(parts[1], out int iterations) || iterations < 10_000) return false;

        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch
        {
            return false;
        }
    }
}
