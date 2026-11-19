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
    public async Task SeedModuleAsync(string name, string code, string? description, int displayOrder, IEnumerable<(string Name, string Code, string? Description)> permissions, CancellationToken cancellationToken = default)
    {
        var moduleCode = SecurityCodes.Normalize(code);
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

        foreach (var p in permissions)
        {
            var permissionCode = SecurityCodes.Normalize(p.Code);
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
