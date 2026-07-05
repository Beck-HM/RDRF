using RDRF.Core;
using Spectre.Console;

namespace RDRF.Cli.Services;

/// <summary>
/// Spectre.Console progress wrapper for backup/restore/push/pull.
/// </summary>

public static class ProgressReporter
{
    public static async Task Run(string title, Func<IProgress<RdrfProgressReport>, Task> action)
    {
        await AnsiConsole.Progress()
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new ElapsedTimeColumn(),
            })
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask(title);
                var progress = new Progress<RdrfProgressReport>(r =>
                {
                    task.MaxValue = Math.Max(task.MaxValue, r.TotalItems);
                    task.Value = Math.Min(r.CurrentItem, r.TotalItems);
                    task.Description = $"{r.Stage}: {r.CurrentItem}/{r.TotalItems}";
                });
                await action(progress);
                task.Value = task.MaxValue;
            });
    }
}







