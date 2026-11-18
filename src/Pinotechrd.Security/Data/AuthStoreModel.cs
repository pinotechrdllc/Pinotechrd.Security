using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Core;

namespace Pinotechrd.Security.Data;

/// <summary>
/// A stored refresh token: the SHA-256 of its value, never the value itself.
/// </summary>
internal sealed class RefreshTokenRecord
{
    public byte[] TokenHash { get; set; } = [];
    public string TenantId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string FamilyId { get; set; } = string.Empty;
    public string? SecurityStamp { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? ConsumedAt { get; set; }
    public DateTime? RevokedAt { get; set; }
}

/// <summary>
/// A refresh token family. A row exists once the family is revoked; a revoked family stays revoked.
/// </summary>
internal sealed class RefreshTokenFamilyRecord
{
    public string FamilyId { get; set; } = string.Empty;
    public DateTime? RevokedAt { get; set; }
}

/// <summary>
/// Model of the persistent refresh token store, mapped when <see cref="PinotechrdSecurityModelOptions.MapRefreshTokens"/> is on.
/// </summary>
internal static class AuthStoreModel
{
    public const string TokensTable = "refresh_tokens";
    public const string FamiliesTable = "refresh_token_families";

    /// <summary>
    /// Maps <see cref="RefreshTokenRecord"/> and <see cref="RefreshTokenFamilyRecord"/> in the tenant schema
    /// (<see langword="null"/> in search_path mode). No foreign key to the users table.
    /// </summary>
    public static void MapRefreshTokens(ModelBuilder modelBuilder, string? tenantSchema)
    {
        modelBuilder.Entity<RefreshTokenRecord>(entity =>
        {
            entity.ToTable(TokensTable, tenantSchema);
            entity.HasKey(e => e.TokenHash);
            entity.Property(e => e.TokenHash).HasColumnName("token_hash").HasMaxLength(RefreshTokenHash.Length).IsRequired();
            entity.Property(e => e.TenantId).HasColumnName("tenant_id").HasMaxLength(128).IsRequired();
            entity.Property(e => e.UserId).HasColumnName("user_id").HasMaxLength(256).IsRequired();
            entity.Property(e => e.FamilyId).HasColumnName("family_id").HasMaxLength(128).IsRequired();
            entity.Property(e => e.SecurityStamp).HasColumnName("security_stamp");
            entity.Property(e => e.ExpiresAt).HasColumnName("expires_at");
            entity.Property(e => e.ConsumedAt).HasColumnName("consumed_at");
            entity.Property(e => e.RevokedAt).HasColumnName("revoked_at");
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.FamilyId);
        });

        modelBuilder.Entity<RefreshTokenFamilyRecord>(entity =>
        {
            entity.ToTable(FamiliesTable, tenantSchema);
            entity.HasKey(e => e.FamilyId);
            entity.Property(e => e.FamilyId).HasColumnName("family_id").HasMaxLength(128).IsRequired();
            entity.Property(e => e.RevokedAt).HasColumnName("revoked_at");
        });
    }
}
