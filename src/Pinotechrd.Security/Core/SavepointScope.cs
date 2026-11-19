using Microsoft.EntityFrameworkCore.Storage;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Runs a unit of work inside the caller's transaction, under a savepoint, so a failure undoes only that work.
/// </summary>
internal static class SavepointScope
{
    /// <summary>
    /// Runs <paramref name="work"/> under <paramref name="savepoint"/>: releases it when the work returns
    /// <see langword="true"/>, and rolls back to it when the work returns <see langword="false"/> or throws.
    /// Without savepoint support the work runs directly, and the caller must roll back its transaction on failure.
    /// </summary>
    /// <exception cref="AggregateException">
    /// The work threw and rolling back to the savepoint failed too; holds both exceptions.
    /// </exception>
    public static async Task<bool> RunAsync(
        IDbContextTransaction transaction,
        string savepoint,
        string operation,
        Func<Task<bool>> work)
    {
        if (!transaction.SupportsSavepoints)
        {
            // Without savepoints a failure cannot be undone here; the caller must roll back its transaction.
            return await work();
        }

        await transaction.CreateSavepointAsync(savepoint);
        bool succeeded;
        try
        {
            succeeded = await work();
        }
        catch (Exception original)
        {
            try
            {
                await transaction.RollbackToSavepointAsync(savepoint);
            }
            catch (Exception rollbackFailure)
            {
                throw new AggregateException(
                    $"{operation} failed, and rolling back to its savepoint failed too; roll back the transaction.",
                    original,
                    rollbackFailure);
            }

            throw;
        }

        if (succeeded)
        {
            await transaction.ReleaseSavepointAsync(savepoint);
        }
        else
        {
            await transaction.RollbackToSavepointAsync(savepoint);
        }

        return succeeded;
    }
}
