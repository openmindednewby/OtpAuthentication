using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Identity.Abstractions.Abstractions;
using OtpAuthentication.Data;
using OtpAuthentication.Entities;

namespace OtpAuthentication.Services;

/// <summary>
/// Database-backed OTP service implementation with Entity Framework Core.
/// </summary>
public class DatabaseOtpService : IOtpService
{
  private readonly OtpDbContext _dbContext;
  private readonly ILogger<DatabaseOtpService> _logger;

  /// <summary>
  /// Initializes a new instance of the <see cref="DatabaseOtpService"/> class.
  /// </summary>
  public DatabaseOtpService(
    OtpDbContext dbContext,
    ILogger<DatabaseOtpService> logger)
  {
    _dbContext = dbContext;
    _logger = logger;
  }

  /// <inheritdoc />
  public string GenerateCode(int length = 6)
  {
    if (length < 4 || length > 10)
      throw new ArgumentOutOfRangeException(nameof(length), "OTP code length must be between 4 and 10");

    var code = string.Empty;
    for (int i = 0; i < length; i++)
    {
      code += RandomNumberGenerator.GetInt32(0, 10).ToString();
    }
    return code;
  }

  /// <inheritdoc />
  public async Task StoreCodeAsync(
    string identifier,
    string code,
    Guid tenantId,
    int expiryMinutes,
    CancellationToken cancellationToken = default)
  {
    _logger.LogInformation("Storing OTP code for identifier {Identifier} in tenant {TenantId}",
      identifier, tenantId);

    // Delete any existing codes for this identifier and tenant
    var existingCodes = await _dbContext.OtpCodes
      .Where(o => o.Identifier == identifier && o.TenantId == tenantId)
      .ToListAsync(cancellationToken);

    if (existingCodes.Any())
    {
      _logger.LogDebug("Removing {Count} existing OTP codes for {Identifier}",
        existingCodes.Count, identifier);
      _dbContext.OtpCodes.RemoveRange(existingCodes);
    }

    // Create new OTP code
    var otpCode = new OtpCode(
      identifier: identifier,
      code: code,
      tenantId: tenantId,
      expiryMinutes: expiryMinutes,
      maxAttempts: 3
    );

    _dbContext.OtpCodes.Add(otpCode);
    await _dbContext.SaveChangesAsync(cancellationToken);

    _logger.LogInformation("OTP code stored successfully for {Identifier}, expires at {ExpiresAt}",
      identifier, otpCode.ExpiresAt);
  }

  /// <inheritdoc />
  public async Task<bool> ValidateCodeAsync(
    string identifier,
    string code,
    Guid tenantId,
    CancellationToken cancellationToken = default)
  {
    _logger.LogInformation("Validating OTP code for identifier {Identifier} in tenant {TenantId}",
      identifier, tenantId);

    var otpCode = await _dbContext.OtpCodes
      .Where(o => o.Identifier == identifier && o.TenantId == tenantId)
      .OrderByDescending(o => o.CreatedAt)
      .FirstOrDefaultAsync(cancellationToken);

    if (otpCode == null)
    {
      _logger.LogWarning("No OTP code found for identifier {Identifier}", identifier);
      return false;
    }

    var isValid = otpCode.Verify(code);

    // Save the incremented attempts
    await _dbContext.SaveChangesAsync(cancellationToken);

    if (isValid)
    {
      _logger.LogInformation("OTP code validated successfully for {Identifier}", identifier);
    }
    else
    {
      _logger.LogWarning("OTP code validation failed for {Identifier}. Attempts: {Attempts}/{MaxAttempts}",
        identifier, otpCode.Attempts, otpCode.MaxAttempts);
    }

    return isValid;
  }

  /// <inheritdoc />
  public async Task MarkAsUsedAsync(
    string identifier,
    string code,
    Guid tenantId,
    CancellationToken cancellationToken = default)
  {
    var otpCode = await _dbContext.OtpCodes
      .Where(o => o.Identifier == identifier && o.Code == code && o.TenantId == tenantId)
      .OrderByDescending(o => o.CreatedAt)
      .FirstOrDefaultAsync(cancellationToken);

    if (otpCode != null)
    {
      otpCode.MarkAsUsed();
      await _dbContext.SaveChangesAsync(cancellationToken);

      _logger.LogInformation("OTP code marked as used for {Identifier}", identifier);
    }
  }

  /// <summary>
  /// Cleans up expired OTP codes from the database.
  /// Call this periodically (e.g., via a background job).
  /// </summary>
  public async Task CleanupExpiredCodesAsync(CancellationToken cancellationToken = default)
  {
    var expiredCodes = await _dbContext.OtpCodes
      .Where(o => o.ExpiresAt < DateTime.UtcNow)
      .ToListAsync(cancellationToken);

    if (expiredCodes.Any())
    {
      _logger.LogInformation("Cleaning up {Count} expired OTP codes", expiredCodes.Count);
      _dbContext.OtpCodes.RemoveRange(expiredCodes);
      await _dbContext.SaveChangesAsync(cancellationToken);
    }
  }
}
