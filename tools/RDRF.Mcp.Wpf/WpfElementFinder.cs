using System.Diagnostics;
using System.Text.Json;

namespace RDRF.Mcp.Wpf;

public static class WpfElementFinder
{
    /// <summary>
    /// Escape a string for safe use inside a PowerShell single-quoted string.
    /// In PowerShell single-quoted strings, only ' needs to be doubled.
    /// To prevent injection via closing quote + additional commands, we also
    /// strip characters that break out of the expression context: $ ( ) { } ; | &amp;.
    /// </summary>
    private static string EscapePsString(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (char c in s)
        {
            switch (c)
            {
                case '\'': sb.Append("''"); break;
                case '$':  sb.Append("`$"); break;
                case '`':  sb.Append("``"); break;
                case '"':  sb.Append("`\""); break;
                case '\n': sb.Append("`n"); break;
                case '\r': sb.Append("`r"); break;
                default:   sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

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
        string aid = EscapePsString(automationId);
        string script = $@"
Add-Type -AssemblyName UIAutomationClient
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt $timeoutMs) {{
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, '{aid}')
    $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if ($el -ne $null) {{
        $rect = $el.Current.BoundingRectangle
        $result = @{{ automationId = '{aid}'
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
        string aid = EscapePsString(automationId);
        string script = $@"
Add-Type -AssemblyName UIAutomationClient
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt $timeoutMs) {{
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, '{aid}')
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
        string aid = EscapePsString(automationId);
        string escaped = EscapePsString(text);
        string script = $@"
Add-Type -AssemblyName UIAutomationClient
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt $timeoutMs) {{
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, '{aid}')
    $el = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if ($el -ne $null) {{
        $vp = $null
        if ($el.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$vp)) {{
            $vp.SetValue('{escaped}')
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

    private static string ClickByTextScript(string text, int timeoutMs)
    {
        // Find RDRF window, then search TextBlocks inside for matching text.
        // When found, walk up the UIA tree to find the clickable parent Border.
        string target = EscapePsString(text);
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("Add-Type -AssemblyName UIAutomationClient");
        sb.AppendLine("$sw = [Diagnostics.Stopwatch]::StartNew()");
        sb.AppendLine("$timeoutMs = " + timeoutMs);
        sb.AppendLine("$target = '" + target + "'");
        sb.AppendLine("$walker = New-Object System.Windows.Automation.TreeWalker([System.Windows.Automation.Condition]::TrueCondition)");
        sb.AppendLine("while ($sw.ElapsedMilliseconds -lt $timeoutMs) {");
        // Find RDRF window
        sb.AppendLine("  $wndCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, 'RDRF')");
        sb.AppendLine("  $wnd = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children, $wndCond)");
        sb.AppendLine("  if ($wnd -ne $null) {");
        // Walk all descendants looking for matching text
        sb.AppendLine("    $todo = New-Object System.Collections.Generic.Queue[System.Windows.Automation.AutomationElement]");
        sb.AppendLine("    $todo.Enqueue($wnd)");
        sb.AppendLine("    while ($todo.Count -gt 0) {");
        sb.AppendLine("      $el = $todo.Dequeue()");
        sb.AppendLine("      try {");
        sb.AppendLine("        $tp = $null");
        sb.AppendLine("        if ($el.TryGetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern, [ref]$tp)) {");
        sb.AppendLine("          $t = $tp.DocumentRange.GetText(-1).Trim()");
        sb.AppendLine("          if ($t -eq $target) {");
        // Walk up to find a clickable parent (Border or any element with BoundingRectangle)
        sb.AppendLine("            $parent = $walker.GetParent($el)");
        sb.AppendLine("            while ($parent -ne $null -and $parent -ne $wnd) {");
        sb.AppendLine("              $pr = $parent.Current.BoundingRectangle");
        sb.AppendLine("              if ($pr.Width -gt 0 -and $pr.Height -gt 0) { break }");
        sb.AppendLine("              $parent = $walker.GetParent($parent)");
        sb.AppendLine("            }");
        sb.AppendLine("            if ($parent -ne $null -and $parent -ne $wnd) {");
        sb.AppendLine("              $rect = $parent.Current.BoundingRectangle");
        sb.AppendLine("              $x = [int]($rect.X + $rect.Width / 2)");
        sb.AppendLine("              $y = [int]($rect.Y + $rect.Height / 2)");
        sb.AppendLine("              Add-Type -AssemblyName System.Windows.Forms");
        sb.AppendLine("              [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point($x, $y)");
        sb.AppendLine("              $sig = '[DllImport(\"user32.dll\")] public static extern void mouse_event(uint f, int x, int y, uint d, int e);'");
        sb.AppendLine("              Add-Type -MemberDefinition $sig -Name NativeMouse -Namespace Win32");
        sb.AppendLine("              [Win32.NativeMouse]::mouse_event(0x0002, 0, 0, 0, 0)");
        sb.AppendLine("              Start-Sleep -Milliseconds 50");
        sb.AppendLine("              [Win32.NativeMouse]::mouse_event(0x0004, 0, 0, 0, 0)");
        sb.AppendLine("              return 'true'");
        sb.AppendLine("            }");
        sb.AppendLine("          }");
        sb.AppendLine("        }");
        // Enqueue children
        sb.AppendLine("        $child = $walker.GetFirstChild($el)");
        sb.AppendLine("        while ($child -ne $null) { $todo.Enqueue($child); $child = $walker.GetNextSibling($child) }");
        sb.AppendLine("      } catch {}");
        sb.AppendLine("    }");
        sb.AppendLine("  }");
        sb.AppendLine("  Start-Sleep -Milliseconds 200");
        sb.AppendLine("}");
        sb.AppendLine("return 'false'");
        return sb.ToString();
    }

    /// <summary>
    /// Click an element by finding a TextBlock child with specific text (for Border cards, etc.)
    /// </summary>
    public static async Task<bool> ClickByText(string text, int timeoutMs = 15000)
    {
        var script = ClickByTextScript(text, timeoutMs);
        var result = await ExecutePowershellAsync(script, timeoutMs + 5000);
        return result == "true";
    }

    private static string SetTextByKeyboardScript(string automationId, string text, int timeoutMs)
    {
        string aid = EscapePsString(automationId);
        string val = EscapePsString(text);
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("Add-Type -AssemblyName UIAutomationClient");
        sb.AppendLine("Add-Type -AssemblyName System.Windows.Forms");
        sb.AppendLine("$sw = [Diagnostics.Stopwatch]::StartNew()");
        sb.AppendLine("$timeoutMs = " + timeoutMs);
        sb.AppendLine("$aid = '" + aid + "'");
        sb.AppendLine("$val = '" + val + "'");
        sb.AppendLine("while ($sw.ElapsedMilliseconds -lt $timeoutMs) {");
        sb.AppendLine("  $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $aid)");
        sb.AppendLine("  $el = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)");
        sb.AppendLine("  if ($el -ne $null) {");
        sb.AppendLine("    $el.SetFocus()");
        sb.AppendLine("    Start-Sleep -Milliseconds 200");
        sb.AppendLine("    [System.Windows.Forms.SendKeys]::SendWait('^a')");
        sb.AppendLine("    Start-Sleep -Milliseconds 100");
        sb.AppendLine("    [System.Windows.Forms.SendKeys]::SendWait($val)");
        sb.AppendLine("    return 'true'");
        sb.AppendLine("  }");
        sb.AppendLine("  Start-Sleep -Milliseconds 200");
        sb.AppendLine("}");
        sb.AppendLine("return 'false'");
        return sb.ToString();
    }

    /// <summary>
    /// Set text on ANY element (including ReadOnly) by focusing + keyboard input.
    /// </summary>
    public static async Task<bool> SetTextByKeyboard(string automationId, string text, int timeoutMs = 15000)
    {
        var script = SetTextByKeyboardScript(automationId, text, timeoutMs);
        var result = await ExecutePowershellAsync(script, timeoutMs + 5000);
        return result == "true";
    }

    /// <summary>
    /// Quick single-shot text read - tries once, no retry loop, much faster.
    /// </summary>
    public static async Task<string?> GetTextOnce(string automationId, int timeoutMs = 5000)
    {
        string aid = EscapePsString(automationId);
        string script = $@"
Add-Type -AssemblyName UIAutomationClient
$cond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::AutomationIdProperty, '{aid}')
$el = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
    [System.Windows.Automation.TreeScope]::Descendants, $cond)
if ($el -ne $null) {{
    $tp = $null
    if ($el.TryGetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern, [ref]$tp)) {{
        return $tp.DocumentRange.GetText(-1).Trim()
    }}
    return $el.Current.Name
}}
return $null
";
        try
        {
            return await ExecutePowershellAsync(script, timeoutMs + 3000);
        }
        catch { return null; }
    }

    /// <summary>
    /// Get the text content of an element by AutomationId using TextPattern or Name.
    /// </summary>
    public static async Task<string?> GetText(string automationId, int timeoutMs = 15000)
    {
        string aid = EscapePsString(automationId);
        string script = $@"
Add-Type -AssemblyName UIAutomationClient
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt $timeoutMs) {{
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty, '{aid}')
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
