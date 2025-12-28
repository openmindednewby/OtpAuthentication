using Microsoft.EntityFrameworkCore;
using OtpAuthentication.Entities;

namespace OtpAuthentication.Data;

/// <summary>
/// Database context for OTP authentication.
/// </summary>
public class OtpDbContext : DbContext
{
  /// <summary>
  /// Initializes a new instance of the <see cref="OtpDbContext"/> class.
  /// </summary>
  public OtpDbContext(DbContextOptions<OtpDbContext> options) : base(options)
  {
  }

  /// <summary>
  /// Gets or sets the OTP codes.
  /// </summary>
  public DbSet<OtpCode> OtpCodes { get; set; } = null!;

  /// <inheritdoc />
  protected override void OnModelCreating(ModelBuilder modelBuilder)
  {
    base.OnModelCreating(modelBuilder);

    modelBuilder.Entity<OtpCode>(entity =>
    {
      entity.ToTable("OtpCodes");

      entity.HasKey(e => e.Id);

      entity.HasIndex(e => new { e.Identifier, e.TenantId, e.ExpiresAt })
        .HasDatabaseName("IX_OtpCodes_Identifier_TenantId_ExpiresAt");

      entity.Property(e => e.Identifier)
        .IsRequired()
        .HasMaxLength(100);

      entity.Property(e => e.Code)
        .IsRequired()
        .HasMaxLength(10);

      entity.Property(e => e.IpAddress)
        .HasMaxLength(45);
    });
  }
}
