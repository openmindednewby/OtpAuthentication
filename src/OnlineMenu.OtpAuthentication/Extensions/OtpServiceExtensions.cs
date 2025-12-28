using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OnlineMenu.Identity.Abstractions.Abstractions;
using OnlineMenu.OtpAuthentication.Data;
using OnlineMenu.OtpAuthentication.Services;

namespace OnlineMenu.OtpAuthentication.Extensions;

/// <summary>
/// Extension methods for registering OTP authentication services.
/// </summary>
public static class OtpServiceExtensions
{
  /// <summary>
  /// Adds database-backed OTP authentication services.
  /// </summary>
  /// <param name="services">The service collection.</param>
  /// <param name="connectionString">The database connection string.</param>
  /// <param name="useInMemoryDatabase">If true, uses an in-memory database for testing.</param>
  /// <returns>The service collection for chaining.</returns>
  public static IServiceCollection AddOtpAuthentication(
    this IServiceCollection services,
    string connectionString,
    bool useInMemoryDatabase = false)
  {
    if (useInMemoryDatabase)
    {
      services.AddDbContext<OtpDbContext>(options =>
        options.UseInMemoryDatabase("OtpDatabase"));
    }
    else
    {
      services.AddDbContext<OtpDbContext>(options =>
        options.UseNpgsql(connectionString));
    }

    services.AddScoped<IOtpService, DatabaseOtpService>();

    return services;
  }

  /// <summary>
  /// Adds database-backed OTP authentication services with custom DbContext configuration.
  /// </summary>
  /// <param name="services">The service collection.</param>
  /// <param name="configureDbContext">Action to configure the DbContext.</param>
  /// <returns>The service collection for chaining.</returns>
  public static IServiceCollection AddOtpAuthentication(
    this IServiceCollection services,
    Action<DbContextOptionsBuilder> configureDbContext)
  {
    services.AddDbContext<OtpDbContext>(configureDbContext);
    services.AddScoped<IOtpService, DatabaseOtpService>();

    return services;
  }
}
