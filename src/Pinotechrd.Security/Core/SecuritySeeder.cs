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
    public async Task SeedModuleAsync(string name, string code, string? description, int displayOrder, IEnumerable<(string Name, string Code, string? Description)> permissions)
    {
        var existingModule = await _db.Modules.FirstOrDefaultAsync(m => m.Code == code.ToUpperInvariant());
        
        if (existingModule == null)
        {
            existingModule = new SecurityModule
            {
                Id = Guid.NewGuid(),
                Name = name,
                Code = code.ToUpperInvariant(),
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
            var existingPermission = await _db.Permissions.FirstOrDefaultAsync(perm => perm.Code == p.Code.ToUpperInvariant());
            if (existingPermission == null)
            {
                var newPermission = new SecurityPermission
                {
                    Id = Guid.NewGuid(),
                    Name = p.Name,
                    Code = p.Code.ToUpperInvariant(),
                    Description = p.Description,
                    Group = name
                };
                
                if (_db is DbContext context)
                {
                    context.Add(newPermission);
                }
            }
        }
        
        if (_db is DbContext dbContext)
        {
            await dbContext.SaveChangesAsync();
        }
    }
}
