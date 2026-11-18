# Pinotechrd.Security.Abstractions

Identity-oriented contracts package for Pinotechrd security integrations.

This package contains abstractions shared across security implementations that extend ASP.NET Core Identity:

- Entities
- Enums
- Interfaces

## Install

```bash
dotnet add package Pinotechrd.Security.Abstractions --prerelease
```

## When to Use

Use this package when you need to integrate with Identity contracts without taking a dependency on the full Pinotechrd.Security runtime service layer.

Typical cases:

- Shared domain contracts across bounded contexts
- Integration layers that extend Identity flows with custom logic
- Plugin architectures with custom security implementations

## Related Package

For full runtime features (identity, JWT, tenancy, authorization), use `Pinotechrd.Security`.

## License

Distributed under the MIT License. See `LICENSE` for more information.
