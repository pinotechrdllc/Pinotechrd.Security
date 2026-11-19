using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Refresh token store kept in the tenant schema through EF Core. Registered by
/// <c>AddPinotechrdEfRefreshTokenStore&lt;TContext&gt;()</c>; requires
/// <see cref="PinotechrdSecurityModelOptions.MapRefreshTokens"/>.
/// </summary>
/// <remarks>
/// <para>
/// Follows the rules of <see cref="IRefreshTokenStore"/>. Tokens are stored as their SHA-256, never in plain text.
/// <see cref="ConsumeAsync"/> is one conditional <c>UPDATE</c>, so of concurrent calls with one token, in this or
/// another instance, exactly one succeeds.
/// </para>
/// <para>
/// Clock: expiry and the consumed and revoked times come from the injected <see cref="TimeProvider"/> (the system
/// clock by default) and are sent to the database as parameters; the database clock is not used. Keep the clocks
/// of every instance synchronised.
/// </para>
/// <para>
/// The store shares the scoped context but never uses its change tracker: it writes with <c>ExecuteUpdate</c> and
/// a parameterised <c>INSERT</c>, and reads without tracking, so it neither saves nor discards the application's
/// pending changes. It runs inside the context's current transaction, if any.
/// </para>
/// <para>
/// Limits: inside an application transaction on PostgreSQL, a duplicate token in <see cref="SaveAsync"/> or a
/// concurrent family revocation aborts the transaction, so the provider's exception surfaces instead of
/// <see cref="InvalidOperationException"/>. With a retrying execution strategy, a consume whose reply was lost
/// is retried and classified <see cref="RefreshTokenConsumeStatus.Reused"/>, which revokes the family: the user
/// signs in again (fails closed).
/// </para>
/// <para>
/// The tables live in the tenant schema. With one schema per tenant another tenant's token is not visible, so it is
/// <see cref="RefreshTokenConsumeStatus.NotFound"/> rather than <see cref="RefreshTokenConsumeStatus.TenantMismatch"/>,
/// and <see cref="RevokeAllForUserAsync"/> reaches the current tenant only.
/// </para>
/// </remarks>
/// <typeparam name="TContext">Context whose model maps the refresh token tables.</typeparam>
internal sealed class EfRefreshTokenStore<TContext> : IRefreshTokenStore
    where TContext : DbContext
{
    private readonly TContext _context;
    private readonly TimeProvider _timeProvider;

    public EfRefreshTokenStore(TContext context, TimeProvider? timeProvider = null)
    {
        _context = context;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    private DateTime UtcNow => _timeProvider.GetUtcNow().UtcDateTime;

    private IQueryable<RefreshTokenRecord> Tokens => Set<RefreshTokenRecord>();

    private IQueryable<RefreshTokenFamilyRecord> Families => Set<RefreshTokenFamilyRecord>();

    /// <inheritdoc />
    /// <exception cref="InvalidOperationException">The token value is already stored.</exception>
    public async Task SaveAsync(
        string userId,
        string tenantId,
        string refreshToken,
        DateTime expiresAtUtc,
        string? familyId = null,
        string? securityStamp = null,
        CancellationToken cancellationToken = default)
    {
        var hash = RefreshTokenHash.Compute(refreshToken);
        var family = familyId ?? Guid.NewGuid().ToString("N");
        var expiresAt = ToUtc(expiresAtUtc);

        try
        {
            await InsertAsync(
                typeof(RefreshTokenRecord),
                [
                    (nameof(RefreshTokenRecord.TokenHash), hash),
                    (nameof(RefreshTokenRecord.TenantId), tenantId),
                    (nameof(RefreshTokenRecord.UserId), userId),
                    (nameof(RefreshTokenRecord.FamilyId), family),
                    (nameof(RefreshTokenRecord.SecurityStamp), securityStamp),
                    (nameof(RefreshTokenRecord.ExpiresAt), expiresAt)
                ],
                cancellationToken);
        }
        catch (DbException ex)
        {
            // Duplicate key; any other failure is rethrown as is. The existing row keeps its state.
            if (!await TokenExistsAsync(hash, cancellationToken)) throw;
            throw new InvalidOperationException("This refresh token is already stored.", ex);
        }

        // A token saved into a revoked family is never consumed: every read and the consume check the family.
    }

    /// <inheritdoc />
    public async Task<RefreshTokenValidationResult> ValidateAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        var token = await FindAsync(RefreshTokenHash.Compute(refreshToken), cancellationToken);
        if (token == null)
        {
            return new RefreshTokenValidationResult(false, Reason: "Refresh token not found");
        }

        if (token.RevokedAt != null || await IsFamilyRevokedAsync(token.FamilyId, cancellationToken))
        {
            return new RefreshTokenValidationResult(false, Reason: "Refresh token revoked");
        }

        if (token.ConsumedAt != null)
        {
            return new RefreshTokenValidationResult(false, Reason: "Refresh token already used");
        }

        if (token.ExpiresAt <= UtcNow)
        {
            return new RefreshTokenValidationResult(false, Reason: "Refresh token expired");
        }

        return new RefreshTokenValidationResult(true, token.UserId, token.TenantId);
    }

    /// <inheritdoc />
    public async Task<RefreshTokenConsumeResult> ConsumeAsync(string refreshToken, string expectedTenantId, CancellationToken cancellationToken = default)
    {
        var hash = RefreshTokenHash.Compute(refreshToken);
        var now = UtcNow;
        var families = Families;

        // The atomic step: every condition in one UPDATE, so only one concurrent caller can match the row.
        var consumed = await Tokens
            .Where(t => t.TokenHash == hash
                        && t.TenantId == expectedTenantId
                        && t.ConsumedAt == null
                        && t.RevokedAt == null
                        && t.ExpiresAt > now
                        && !families.Any(f => f.FamilyId == t.FamilyId && f.RevokedAt != null))
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.ConsumedAt, (DateTime?)now), cancellationToken);

        var token = await FindAsync(hash, cancellationToken);
        if (consumed == 1 && token != null)
        {
            return new RefreshTokenConsumeResult(
                RefreshTokenConsumeStatus.Consumed, token.UserId, token.TenantId, token.FamilyId, token.SecurityStamp);
        }

        // Not consumed: classify in the order of the contract.
        if (token == null)
        {
            return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.NotFound);
        }

        if (!string.Equals(token.TenantId, expectedTenantId, StringComparison.Ordinal))
        {
            return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.TenantMismatch);
        }

        if (await IsFamilyRevokedAsync(token.FamilyId, cancellationToken))
        {
            return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Revoked);
        }

        if (token.ConsumedAt != null)
        {
            // Reuse, even if the token has expired or was revoked on its own since.
            await RevokeFamilyAsync(token.FamilyId, now, cancellationToken);
            return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Reused);
        }

        if (token.RevokedAt != null)
        {
            return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Revoked);
        }

        if (token.ExpiresAt <= now)
        {
            return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Expired);
        }

        // Only reachable when the row appeared between the UPDATE and the read: fail closed.
        return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.NotFound);
    }

    /// <inheritdoc />
    public async Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        var hash = RefreshTokenHash.Compute(refreshToken);
        var now = UtcNow;
        await Tokens
            .Where(t => t.TokenHash == hash && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, (DateTime?)now), cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>Reaches the tokens of the current tenant schema only.</remarks>
    public async Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        var now = UtcNow;
        var familyIds = await Tokens
            .Where(t => t.UserId == userId)
            .Select(t => t.FamilyId)
            .Distinct()
            .ToListAsync(cancellationToken);

        // Revoking the families also covers a token a concurrent rotation saves after this call.
        foreach (var familyId in familyIds)
        {
            await RevokeFamilyAsync(familyId, now, cancellationToken);
        }

        await Tokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, (DateTime?)now), cancellationToken);
    }

    private async Task RevokeFamilyAsync(string familyId, DateTime now, CancellationToken cancellationToken)
    {
        // Keeps the first revocation time; a revoked family stays revoked.
        await Families
            .Where(f => f.FamilyId == familyId && f.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(f => f.RevokedAt, (DateTime?)now), cancellationToken);

        if (await Families.AnyAsync(f => f.FamilyId == familyId, cancellationToken)) return;

        try
        {
            await InsertAsync(
                typeof(RefreshTokenFamilyRecord),
                [
                    (nameof(RefreshTokenFamilyRecord.FamilyId), familyId),
                    (nameof(RefreshTokenFamilyRecord.RevokedAt), now)
                ],
                cancellationToken);
        }
        catch (DbException)
        {
            // Tolerated only when a concurrent call revoked the family first.
            if (!await IsFamilyRevokedAsync(familyId, cancellationToken)) throw;
        }
    }

    private Task<RefreshTokenRecord?> FindAsync(byte[] hash, CancellationToken cancellationToken) =>
        Tokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == hash, cancellationToken);

    private Task<bool> TokenExistsAsync(byte[] hash, CancellationToken cancellationToken) =>
        Tokens.AnyAsync(t => t.TokenHash == hash, cancellationToken);

    private Task<bool> IsFamilyRevokedAsync(string familyId, CancellationToken cancellationToken) =>
        Families.AnyAsync(f => f.FamilyId == familyId && f.RevokedAt != null, cancellationToken);

    /// <summary>
    /// Inserts one row with a parameterised <c>INSERT</c> built from the model's table and column names, without
    /// the change tracker, so the application's pending changes are not saved with it.
    /// </summary>
    private Task<int> InsertAsync(Type entityClrType, (string Property, object? Value)[] values, CancellationToken cancellationToken)
    {
        var entityType = FindEntityType(entityClrType);
        var table = StoreObjectIdentifier.Table(entityType.GetTableName()!, entityType.GetSchema());
        var sql = _context.GetService<ISqlGenerationHelper>();

        var properties = values.Select(v => entityType.FindProperty(v.Property)!).ToArray();
        var columns = properties.Select(p => sql.DelimitIdentifier(p.GetColumnName(table)!));
        var placeholders = values.Select((_, i) => "{" + i + "}");
        var command = $"INSERT INTO {sql.DelimitIdentifier(table.Name, table.Schema)} ({string.Join(", ", columns)}) " +
                      $"VALUES ({string.Join(", ", placeholders)})";

        // Typed parameters from each column's type mapping: a bare null (DBNull) has no store type, and the
        // mapping also applies any value converter the model configures.
        using var factory = _context.Database.GetDbConnection().CreateCommand();
        var parameters = properties
            .Select((property, i) => (object)property.GetRelationalTypeMapping()
                .CreateParameter(factory, "p" + i, values[i].Value, property.IsNullable))
            .ToArray();

        return _context.Database.ExecuteSqlRawAsync(command, parameters, cancellationToken);
    }

    private IQueryable<T> Set<T>() where T : class
    {
        FindEntityType(typeof(T));
        return _context.Set<T>();
    }

    private IEntityType FindEntityType(Type clrType) =>
        _context.Model.FindEntityType(clrType)
        ?? throw new InvalidOperationException(
            $"{typeof(TContext).Name} does not map the refresh token tables. Set MapRefreshTokens = true in " +
            "UsePinotechrdSecurity(o => o.MapRefreshTokens = true), add a migration, and apply it to every tenant schema.");

    private static DateTime ToUtc(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
    };
}
