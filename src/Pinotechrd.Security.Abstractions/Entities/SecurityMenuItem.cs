namespace Pinotechrd.Security.Entities;

/// <summary>
/// Represents an authorized navigation item within the security system.
/// </summary>
public class SecurityMenuItem
{
    /// <summary>
    /// Gets or sets the localization resource key (e.g., "Menu_Dashboard").
    /// </summary>
    public required string TitleKey { get; init; }

    /// <summary>
    /// Gets or sets the navigation path or URI.
    /// </summary>
    public string? Path { get; init; }

    /// <summary>
    /// Gets or sets the icon identifier for the UI.
    /// </summary>
    public string? Icon { get; init; }

    /// <summary>
    /// Gets or sets the display order.
    /// </summary>
    public int Order { get; init; }

    /// <summary>
    /// Gets or sets the specific module this item belongs to (e.g., "Orders").
    /// If null, it is considered a core/global item.
    /// </summary>
    public string? ModuleCode { get; init; }

    /// <summary>
    /// Gets or sets the list of permissions required to view this item (e.g., ["Orders.Read"]).
    /// If empty, the item might still be subject to module/subscription checks.
    /// </summary>
    public List<string> RequiredPermissions { get; init; } = [];

    /// <summary>
    /// Gets or sets the hierarchical child items.
    /// </summary>
    public List<SecurityMenuItem> Children { get; init; } = [];
}
