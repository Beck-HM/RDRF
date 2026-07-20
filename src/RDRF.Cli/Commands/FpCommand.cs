using RDRF.Cli.Services;
using RDRF.Core.PasswordManager;
using Spectre.Console;
using System.CommandLine;
using System.Security.Cryptography;
using System.Text;

namespace RDRF.Cli.Commands;

public class FpCommand : Command
{
    public FpCommand(PasswordManager passwordManager) : base("fp", "Manage FastPasswords (shortcut encryption keys)")
    {
        var keyArg = new Argument<string>("key") { Description = "FastPassword key" };
        var deleteKeyArg = new Argument<string>("key") { Description = "FastPassword key to delete" };
        var getKeyArg = new Argument<string>("key") { Description = "FastPassword key" };

        var setCmd = new Command("set", "Store or overwrite a FastPassword (interactive)");
        setCmd.Arguments.Add(keyArg);
        setCmd.SetAction((ParseResult parseResult) =>
        {
            var key = parseResult.GetValue(keyArg);
            byte[] value = PasswordProvider.ReadInteractive("Enter password: ");
            if (value.Length == 0)
            {
                AnsiConsole.MarkupLine("[red]Password cannot be empty.[/]");
                return 1;
            }
            byte[] confirm = PasswordProvider.ReadInteractive("Confirm password: ");
            if (!value.AsSpan().SequenceEqual(confirm.AsSpan()))
            {
                CryptographicOperations.ZeroMemory(value);
                CryptographicOperations.ZeroMemory(confirm);
                AnsiConsole.MarkupLine("[red]Passwords do not match.[/]");
                return 1;
            }
            CryptographicOperations.ZeroMemory(confirm);
            try
            {
                passwordManager.Set(key, value);
                AnsiConsole.MarkupLine($"[green]FastPassword '{key}' stored.[/]");
                return 0;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(value);
            }
        });

        var listCmd = new Command("list", "List all FastPassword keys");
        listCmd.SetAction((ParseResult parseResult) =>
        {
            passwordManager.Initialize();
            var keys = passwordManager.ListKeys();
            if (keys.Length == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No FastPasswords stored.[/]");
                return 0;
            }
            var table = new Table();
            table.Border(TableBorder.Rounded);
            table.AddColumn("Key");
            table.AddColumn("Backups");
            foreach (var k in keys)
            {
                var detail = passwordManager.GetKeyDetail(k);
                table.AddRow(k, detail.Length.ToString());
            }
            AnsiConsole.Write(table);
            return 0;
        });

        var deleteCmd = new Command("delete", "Delete a FastPassword");
        deleteCmd.Arguments.Add(deleteKeyArg);
        deleteCmd.SetAction((ParseResult parseResult) =>
        {
            var key = parseResult.GetValue(deleteKeyArg);
            AnsiConsole.MarkupLine($"[yellow]WARNING: You are about to permanently delete FastPassword '{key}'.[/]");
            AnsiConsole.Markup("[gray]Type the key name to confirm: [/]");
            string? confirm = Console.ReadLine()?.Trim();
            if (confirm != key)
            {
                AnsiConsole.MarkupLine("[red]Confirmation failed. Deletion aborted.[/]");
                return 1;
            }
            if (passwordManager.Delete(key))
                AnsiConsole.MarkupLine($"[green]FastPassword '{key}' deleted.[/]");
            else
                AnsiConsole.MarkupLine($"[yellow]FastPassword '{key}' not found.[/]");
            return 0;
        });

        var getCmd = new Command("get", "Show FastPassword details");
        getCmd.Arguments.Add(getKeyArg);
        getCmd.SetAction((ParseResult parseResult) =>
        {
            var key = parseResult.GetValue(getKeyArg);
            passwordManager.Initialize();
            var pwVal = passwordManager.GetByKey(key);
            if (pwVal == null)
            {
                AnsiConsole.MarkupLine($"[red]FastPassword '{key}' not found.[/]");
                return 1;
            }
            var detail = passwordManager.GetKeyDetail(key);
            AnsiConsole.MarkupLine($"[green]Key:[/] {key}");
            AnsiConsole.MarkupLine($"[green]Backups:[/] {detail.Length}");
            foreach (var b in detail)
                AnsiConsole.MarkupLine($"  [gray]{b.IndexHash[..16]}... ({b.CreatedAt})[/]");
            return 0;
        });

        Add(setCmd);
        Add(listCmd);
        Add(deleteCmd);
        Add(getCmd);
    }
}
