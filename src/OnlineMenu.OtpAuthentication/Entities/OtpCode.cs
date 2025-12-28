using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace OtpAuthentication.Entities;

/// <summary>
/// Entity for storing OTP codes with automatic expiry and security features.
/// </summary>
public class OtpCode
{
  /// <summary>
  /// Gets the primary key.
  /// </summary>
  [Key]
  [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
  public int Id { get; private set; }

  /// <summary>
  /// Gets the phone number or email that received the OTP.
  /// </summary>
  [Required]
  [MaxLength(100)]
  public string Identifier { get; private set; }

  /// <summary>
  /// Gets the OTP code.
  /// </summary>
  [Required]
  [MaxLength(10)]
  public string Code { get; private set; }

  /// <summary>
  /// Gets the creation timestamp.
  /// </summary>
  [Required]
  public DateTime CreatedAt { get; private set; }

  /// <summary>
  /// Gets the expiration timestamp.
  /// </summary>
  [Required]
  public DateTime ExpiresAt { get; private set; }

  /// <summary>
  /// Gets a value indicating whether the OTP has been used.
  /// </summary>
  [Required]
  public bool IsUsed { get; private set; }

  /// <summary>
  /// Gets the tenant ID for multi-tenant isolation.
  /// </summary>
  [Required]
  public Guid TenantId { get; private set; }

  /// <summary>
  /// Gets the number of verification attempts.
  /// </summary>
  [Required]
  public int Attempts { get; private set; }

  /// <summary>
  /// Gets the maximum allowed attempts.
  /// </summary>
  [Required]
  public int MaxAttempts { get; private set; }

  /// <summary>
  /// Gets the IP address that requested the OTP (for security logging).
  /// </summary>
  [MaxLength(45)] // IPv6 max length
  public string? IpAddress { get; private set; }

  /// <summary>
  /// Parameterless constructor for EF Core.
  /// </summary>
  private OtpCode()
  {
    Identifier = string.Empty;
    Code = string.Empty;
  }

  /// <summary>
  /// Initializes a new instance of the <see cref="OtpCode"/> class.
  /// </summary>
  /// <param name="identifier">The phone number or email.</param>
  /// <param name="code">The OTP code.</param>
  /// <param name="tenantId">The tenant identifier.</param>
  /// <param name="expiryMinutes">Expiry time in minutes.</param>
  /// <param name="maxAttempts">Maximum verification attempts.</param>
  /// <param name="ipAddress">Optional IP address for security logging.</param>
  public OtpCode(
    string identifier,
    string code,
    Guid tenantId,
    int expiryMinutes,
    int maxAttempts = 3,
    string? ipAddress = null)
  {
    Identifier = identifier;
    Code = code;
    TenantId = tenantId;
    CreatedAt = DateTime.UtcNow;
    ExpiresAt = DateTime.UtcNow.AddMinutes(expiryMinutes);
    IsUsed = false;
    Attempts = 0;
    MaxAttempts = maxAttempts;
    IpAddress = ipAddress;
  }

  /// <summary>
  /// Gets a value indicating whether the OTP is still valid (not expired and not used).
  /// </summary>
  public bool IsValid => !IsUsed && DateTime.UtcNow < ExpiresAt;

  /// <summary>
  /// Gets a value indicating whether max attempts have been reached.
  /// </summary>
  public bool HasReachedMaxAttempts => Attempts >= MaxAttempts;

  /// <summary>
  /// Verifies the provided code matches this OTP.
  /// </summary>
  /// <param name="providedCode">The code to verify.</param>
  /// <returns>True if the code matches and is valid; otherwise, false.</returns>
  public bool Verify(string providedCode)
  {
    if (!IsValid) return false;
    if (HasReachedMaxAttempts) return false;

    IncrementAttempts();

    return Code == providedCode;
  }

  /// <summary>
  /// Increments the attempt counter.
  /// </summary>
  public void IncrementAttempts()
  {
    Attempts++;
  }

  /// <summary>
  /// Marks the OTP as used.
  /// </summary>
  public void MarkAsUsed()
  {
    IsUsed = true;
  }
}
