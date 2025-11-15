using System.Diagnostics;
using System.Text.Json;

namespace RDRF.Mcp.Wpf;

public static class WpfElementFinder
{
    public static async Task<string> ExecutePowershellAsync(string script, int timeoutMs = 30000)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell",
            ArgumentList = { "-NoProfile", "-NonInteractive", "-Command", script },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var proc = new Process { StartInfo = psi };
        proc.Start();

        var outTask = proc.StandardOutput.ReadToEndAsync();
        var errTask = proc.StandardError.ReadToEndAsync();

        if (!proc.WaitForExit(timeoutMs))
        {
            proc.Kill();
            throw new TimeoutException($"PowerShell script timed out after {timeoutMs}ms");
        }

        var stdout = await outTask;
        var stderr = await errTask;

        if (proc.ExitCode != 0)
            throw new InvalidOperationException($"PowerShell error (exit {proc.ExitCode}): {stderr}");

        return stdout.Trim();
    }

    /// <summary>
    /// Find a UIA element by AutomationId and return its bounding rectangle.
    /// Uses PowerShell UIAutomation to avoid process/thread affinity issues.
    /// </summary>
    public static async Task<string?> FindElementByAutomationId(string automationId, int timeoutMs = 15000)
    {
        string script = $@"
Add-Type -AssemblyName UIAutomationClient
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt $timeoutMs) {{
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, '$automationId')
    $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if ($el -ne $null) {{
        $rect = $el.Current.BoundingRectangle
        $result = @{{ automationId = '$automationId'
                     x = $rect.X; y = $rect.Y
                     width = $rect.Width; height = $rect.Height
                     name = $el.Current.Name
                     controlType = $el.Current.ControlType.ProgrammaticName }}
        return ConvertTo-Json -Compress $result
    }}
    Start-Sleep -Milliseconds 200
}}
return $null
".Replace("$timeoutMs", timeoutMs.ToString());

        try
        {
            var result = await ExecutePowershellAsync(script, timeoutMs + 5000);
            return string.IsNullOrEmpty(result) || result == "null" ? null : result;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Click a button by AutomationId using UIA InvokePattern.
    /// </summary>
    public static async Task<bool> ClickButton(string automationId, int timeoutMs = 15000)
    {
        string script = $@"
Add-Type -AssemblyName UIAutomationClient
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt $timeoutMs) {{
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, '$automationId')
    $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if ($el -ne $null) {{
        $invoke = $null
        if ($el.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$invoke)) {{
            $invoke.Invoke()
            return 'true'
        }}
    }}
    Start-Sleep -Milliseconds 200
}}
return 'false'
";
        var result = await ExecutePowershellAsync(script, timeoutMs + 5000);
        return result == "true";
    }

    /// <summary>
    /// Set text on a TextBox by AutomationId using ValuePattern.
    /// </summary>
    public static async Task<bool> SetText(string automationId, string text, int timeoutMs = 15000)
    {
        string escaped = text.Replace("'", "''");
        string script = $@"
Add-Type -AssemblyName UIAutomationClient
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt $timeoutMs) {{
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, '$automationId')
    $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if ($el -ne $null) {{
        $vp = $null
        if ($el.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vp)) {{
            $vp.SetValue('$escaped')
            return 'true'
        }}
    }}
    Start-Sleep -Milliseconds 200
}}
return 'false'
";
        var result = await ExecutePowershellAsync(script, timeoutMs + 5000);
        return result == "true";
    }

    /// <summary>
    /// Get the text content of an element by AutomationId using TextPattern or Name.
    /// </summary>
    public static async Task<string?> GetText(string automationId, int timeoutMs = 15000)
    {
        string script = $@"
Add-Type -AssemblyName UIAutomationClient
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt $timeoutMs) {{
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, '$automationId')
    $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if ($el -ne $null) {{
        $tp = $null
        if ($el.TryGetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern, [ref]$tp)) {{
            $text = $tp.DocumentRange.GetText(-1)
            return $text
        }}
        return $el.Current.Name
    }}
    Start-Sleep -Milliseconds 200
}}
return $null
";
        try
        {
            return await ExecutePowershellAsync(script, timeoutMs + 5000);
        }
        catch { return null; }
    }
}
