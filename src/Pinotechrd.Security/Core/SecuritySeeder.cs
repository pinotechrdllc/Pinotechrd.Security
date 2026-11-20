using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Provides utility methods to seed security infrastructure.
/// </summary>
public class SecuritySeeder
{
    private readonly ISecurityDbContext _db;

    /// <summary>
    /// Initializes the seeder.
    /// </summary>
    public SecuritySeeder(ISecurityDbContext db)
    {
        _db = db;
    }

    /// <summary>
    /// Seeds a module and its associated permissions if they don't exist.
    /// </summary>
    /// <remarks>
    /// Codes are stored normalised (trimmed, upper case). A new module gets the id
    /// <see cref="SecurityModuleId.FromCode"/>, the same in every tenant, so a plan in the shared catalog can
    /// refer to it. Every permission is linked to the module; an existing permission without a module is linked.
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// The module code is not a valid code without a dot, or a permission code is not <c>MODULE.PERMISSION</c> for this
    /// module. Every code is checked before anything is added to the context, so a refused call leaves nothing pending.
    /// </exception>
    public async Task SeedModuleAsync(string name, string code, string? description, int displayOrder, IEnumerable<(string Name, string Code, string? Description)> permissions, CancellationToken cancellationToken = default)
    {
        if (!SecurityCodes.TryNormalizeModule(code, out var moduleCode))
        {
            throw new ArgumentException(
                "A module code must be 1 to 100 characters from A-Z, a-z, 0-9, '_' and '-' (no dot).", nameof(code));
        }

        // Every permission is checked first, so a bad entry leaves nothing pending in the context. A permission is
        // MODULE.PERMISSION and belongs to the module it names: CanAccessAsync looks it up that way, so any other code
        // could never be granted, or would be granted by another module's plan entry.
        var wanted = new List<(string Name, string Code, string? Description)>();
        foreach (var p in permissions)
        {
            if (!SecurityCodes.TryNormalizeStoredPermission(p.Code, out var normalized, out var permissionModule)
                || !string.Equals(permissionModule, moduleCode, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    $"Permission code must be '{moduleCode}.<PERMISSION>' for module '{moduleCode}'.", nameof(permissions));
            }

            wanted.Add((p.Name, normalized, p.Description));
        }

        var existingModule = await _db.Modules.FirstOrDefaultAsync(m => m.Code == moduleCode, cancellationToken);

        if (existingModule == null)
        {
            existingModule = new SecurityModule
            {
                Id = SecurityModuleId.FromCode(moduleCode),
                Name = name,
                Code = moduleCode,
                Description = description,
                DisplayOrder = displayOrder,
                IsActive = true
            };

            if (_db is DbContext context)
            {
                context.Add(existingModule);
            }
        }

        foreach (var p in wanted)
        {
            var permissionCode = p.Code;

            var existingPermission = await _db.Permissions.FirstOrDefaultAsync(perm => perm.Code == permissionCode, cancellationToken);
            if (existingPermission == null)
            {
                var newPermission = new SecurityPermission
                {
                    Id = Guid.NewGuid(),
                    ModuleId = existingModule.Id,
                    Name = p.Name,
                    Code = permissionCode,
                    Description = p.Description,
                    Group = name
                };

                if (_db is DbContext context)
                {
                    context.Add(newPermission);
                }
            }
            else if (existingPermission.ModuleId == Guid.Empty)
            {
                existingPermission.ModuleId = existingModule.Id;
            }
        }

        if (_db is DbContext dbContext)
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
    }
}
