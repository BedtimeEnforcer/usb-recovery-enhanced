param([string]$Exe = (Join-Path $PSScriptRoot '..\dist\U盘修复助手.exe'), [switch]$Enhanced, [string]$ScreenshotDirectory)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing
# Only launches our own process and checks its empty-clean dialog.
# Does not scan, clean files, access removable media or request a reboot.
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class ReportSmoke {
    public delegate bool Callback(IntPtr h, IntPtr p);
    [DllImport("user32.dll")] public static extern bool EnumWindows(Callback cb, IntPtr p);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, Callback cb, IntPtr p);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint id);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder b, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder b, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageTimeout(IntPtr h, uint msg, IntPtr w, StringBuilder text, uint flags, uint timeout, out IntPtr result);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out Rect rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int command);
    [DllImport("user32.dll")] public static extern bool UpdateWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int index);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
    public static IntPtr Find(int processId, string cls) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((h,p) => {
            uint id; GetWindowThreadProcessId(h, out id);
            var b = new StringBuilder(256); GetClassName(h,b,b.Capacity);
            if (id == processId && b.ToString() == cls) { found=h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    public static string Text(IntPtr h) {
        var all = new StringBuilder();
        EnumChildWindows(h, (c,p) => {
            var b=new StringBuilder(32768); IntPtr result;
            SendMessageTimeout(c,13,(IntPtr)b.Capacity,b,2,3000,out result);
            all.AppendLine(b.ToString()); return true;
        }, IntPtr.Zero);
        return all.ToString();
    }
    public static IntPtr ChildByClass(IntPtr parent, string cls) {
        IntPtr found=IntPtr.Zero;
        EnumChildWindows(parent,(h,p)=>{
            var b=new StringBuilder(256); GetClassName(h,b,b.Capacity);
            if(b.ToString()==cls) { found=h;return false; } return true;
        },IntPtr.Zero);
        return found;
    }
}
'@
$app = Start-Process -FilePath (Resolve-Path -LiteralPath $Exe).Path -WindowStyle Hidden -PassThru
function Wait-Window([string]$className, [bool]$present = $true) {
    $deadline = (Get-Date).AddSeconds(15)
    do {
        $h = [ReportSmoke]::Find($app.Id, $className)
        if (($h -ne [IntPtr]::Zero) -eq $present) { return $h }
        if ($app.HasExited) { throw 'Application exited unexpectedly' }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    throw "Window timeout: $className present=$present"
}
function Save-Window([IntPtr]$handle, [string]$fileName) {
    if (-not $ScreenshotDirectory) { return }
    # Show only the tested window briefly when an explicit visual review is requested.
    [ReportSmoke]::ShowWindow($handle, 4) | Out-Null
    [ReportSmoke]::UpdateWindow($handle) | Out-Null
    $r = New-Object ReportSmoke+Rect
    [ReportSmoke]::GetWindowRect($handle, [ref]$r) | Out-Null
    $bitmap = New-Object System.Drawing.Bitmap (($r.Right-$r.Left),($r.Bottom-$r.Top))
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $dc = $graphics.GetHdc()
    try {
        if (-not [ReportSmoke]::PrintWindow($handle,$dc,0)) { throw 'Window capture failed' }
    } finally { $graphics.ReleaseHdc($dc); $graphics.Dispose() }
    try { $bitmap.Save((Join-Path $ScreenshotDirectory $fileName),[System.Drawing.Imaging.ImageFormat]::Png) }
    finally { $bitmap.Dispose() }
}
try {
    $main = Wait-Window 'UsbRecoveryNative'
    $guide = Wait-Window '#32770'
    $guideDeadline = (Get-Date).AddSeconds(5)
    do {
        $guideElement = [System.Windows.Automation.AutomationElement]::FromHandle($guide)
        $guideChildren = $guideElement.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
        $guideText = ($guideChildren | ForEach-Object { $_.Current.Name } | Where-Object { $_ } | Select-Object -Unique) -join "`r`n"
        if ($guideText.Contains('【制作人】')) { break }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $guideDeadline)
    foreach ($required in @('【病毒简介】','剪贴板地址替换','更换密码','新助记词','【使用步骤】','清理完成后重启电脑','【制作人】','李晓达——因机务段带毒电脑过多，U 盘反复感染，实在受不了了而开发本工具。')) {
        if (-not $guideText.Contains($required)) { throw "Missing original guide content: $required" }
    }
    if ($guideText.Contains('【加强版】')) { throw 'Startup guide still uses enhanced technical introduction' }
    'PASS original virus introduction, steps and creator shown at startup'
    [ReportSmoke]::PostMessage($guide, 0x466, [IntPtr]1, [IntPtr]::Zero) | Out-Null
    Wait-Window '#32770' $false | Out-Null
    [ReportSmoke]::PostMessage($main, 0x111, [IntPtr]102, [IntPtr]::Zero) | Out-Null
    $dialog = Wait-Window '#32770'
    # TaskDialog body uses DirectUI; GetWindowText only sees its OK button.
    $element = [System.Windows.Automation.AutomationElement]::FromHandle($dialog)
    $children = $element.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    $text = ($children | ForEach-Object { $_.Current.Name } | Where-Object { $_ } | Select-Object -Unique) -join "`r`n"
    if ($text -notmatch '请先检查病毒' -or $text -notmatch '开始检查' -or $text -match '您的电脑没问题') {
        throw "Unexpected empty-clean dialog: $text"
    }
    'PASS native startup and empty-clean dialog'
    $text.Trim()
    [ReportSmoke]::PostMessage($dialog, 0x466, [IntPtr]1, [IntPtr]::Zero) | Out-Null
    Wait-Window '#32770' $false | Out-Null
    if ($Enhanced) {
        $log = [ReportSmoke]::ChildByClass($main, 'Edit')
        if ($log -eq [IntPtr]::Zero -or ([ReportSmoke]::GetWindowLong($log,-16) -band 0x10000000)) { throw 'Log should be collapsed by default' }
        'PASS detailed log is collapsed by default'
        Save-Window $main 'ui-main.png'
        [ReportSmoke]::PostMessage($main,0x111,[IntPtr]110,[IntPtr]::Zero) | Out-Null
        $deadline=(Get-Date).AddSeconds(5)
        while (-not ([ReportSmoke]::GetWindowLong($log,-16) -band 0x10000000) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 100 }
        if (-not ([ReportSmoke]::GetWindowLong($log,-16) -band 0x10000000)) { throw 'Log expansion failed' }
        $logRect=New-Object ReportSmoke+Rect; $mainRect=New-Object ReportSmoke+Rect
        [ReportSmoke]::GetWindowRect($log,[ref]$logRect) | Out-Null
        [ReportSmoke]::GetWindowRect($main,[ref]$mainRect) | Out-Null
        if (($logRect.Bottom-$logRect.Top) -gt (($mainRect.Bottom-$mainRect.Top)*0.35)) { throw 'Expanded log occupies too much of the window' }
        Save-Window $main 'ui-main-expanded.png'
        [ReportSmoke]::PostMessage($main,0x111,[IntPtr]110,[IntPtr]::Zero) | Out-Null
        $deadline=(Get-Date).AddSeconds(5)
        while (([ReportSmoke]::GetWindowLong($log,-16) -band 0x10000000) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 100 }
        if ([ReportSmoke]::GetWindowLong($log,-16) -band 0x10000000) { throw 'Log collapse failed' }
        'PASS log expands compactly and collapses again'
        [ReportSmoke]::PostMessage($main, 0x111, [IntPtr]109, [IntPtr]::Zero) | Out-Null
        $rules = Wait-Window 'UsbEnhancedRules'
        $deadline = (Get-Date).AddSeconds(5)
        do {
            $ruleText = [ReportSmoke]::Text($rules)
            if ($ruleText -match '15 条 SHA-256' -and $ruleText -match '来源：') { break }
            Start-Sleep -Milliseconds 100
        } while ((Get-Date) -lt $deadline)
        if ($ruleText -notmatch '15 条 SHA-256' -or $ruleText -notmatch 'PlugX' -or $ruleText -notmatch 'Raspberry Robin' -or $ruleText -notmatch '来源：') { throw 'Enhanced rule catalog missing' }
        Save-Window $rules 'ui-rules.png'
        'PASS enhanced scrollable catalog contains fingerprints, sources and solutions'
        [ReportSmoke]::PostMessage($rules, 0x10, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        Wait-Window 'UsbEnhancedRules' $false | Out-Null
    }
    [ReportSmoke]::PostMessage($main, 0x10, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    if (-not $app.WaitForExit(5000) -or $app.ExitCode -ne 0) { throw 'Application did not exit cleanly' }
    'PASS native application closes normally'
} finally {
    if (-not $app.HasExited) { $app.Kill(); $app.WaitForExit() }
}
