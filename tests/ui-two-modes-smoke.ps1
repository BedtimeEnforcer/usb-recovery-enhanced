param([string]$Exe = (Join-Path $PSScriptRoot '..\dist\hotfix-v0.6.2\U盘修复助手-加强版.exe'), [switch]$Enhanced, [string]$ScreenshotDirectory)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing
# Checks the home, warning and device picker; reads volume labels only.
# Does not start scans, cleanup, recovery or reboot.
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
function Dialog-Text([IntPtr]$handle) {
    $element=[System.Windows.Automation.AutomationElement]::FromHandle($handle)
    $children=$element.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
    return (($children | ForEach-Object {$_.Current.Name} | Where-Object {$_} | Select-Object -Unique) -join "`r`n")
}
try {
    $main=Wait-Window 'UsbRecoveryNative'
    Start-Sleep -Milliseconds 400
    if ([ReportSmoke]::Find($app.Id,'#32770') -ne [IntPtr]::Zero) {throw 'Unexpected startup popup'}
    $text=[ReportSmoke]::Text($main)
    if (-not $text.Contains('全盘杀毒') -or -not $text.Contains('U盘专杀')) {throw 'Missing mode buttons'}
    foreach ($id in @(103,107,108,113)) {if ([ReportSmoke]::GetDlgItem($main,$id) -ne [IntPtr]::Zero) {throw "Obsolete home control: $id"}}
    'PASS two mode buttons, no drive selector or separate recovery on home'
    Save-Window $main 'ui-main.png'
    [ReportSmoke]::PostMessage($main,0x111,[IntPtr]106,[IntPtr]::Zero) | Out-Null
    $about=Wait-Window '#32770'
    Start-Sleep -Milliseconds 300
    $aboutText=Dialog-Text $about
    if (-not $aboutText.Contains('制作人李晓达，U盘经常被机务段病毒电脑感染，实在受不了，做了此工具，请传给需要的人。')) {throw 'Creator introduction does not match requested text'}
    Save-Window $about 'ui-about.png'
    [ReportSmoke]::PostMessage($about,0x466,[IntPtr]1,[IntPtr]::Zero) | Out-Null
    Wait-Window '#32770' $false | Out-Null
    'PASS requested creator introduction appears in actual executable'

    [ReportSmoke]::PostMessage($main,0x111,[IntPtr]102,[IntPtr]::Zero) | Out-Null
    $warning=Wait-Window '#32770'
    Start-Sleep -Milliseconds 300
    $warningText=Dialog-Text $warning
    if (-not $warningText.Contains('仅供未中病毒的电脑使用') -or -not $warningText.Contains('建议使用“全盘杀毒”')) {throw "Missing USB warning: $warningText"}
    if ($warningText.Length -gt 180) {throw 'USB warning is too verbose'}
    Save-Window $warning 'ui-usb-warning.png'
    [ReportSmoke]::PostMessage($warning,0x466,[IntPtr]502,[IntPtr]::Zero) | Out-Null
    $picker=Wait-Window 'UsbOnlyPicker'
    Start-Sleep -Milliseconds 300
    $pickerText=[ReportSmoke]::Text($picker)
    if (-not $pickerText.Contains('开始查杀并恢复') -or -not $pickerText.Contains('刷新')) {throw 'Missing USB picker controls'}
    Save-Window $picker 'ui-usb-picker.png'
    'PASS concise USB warning appears before the separate device picker'
    [ReportSmoke]::PostMessage($picker,0x111,[IntPtr]3,[IntPtr]::Zero) | Out-Null
    Wait-Window 'UsbOnlyPicker' $false | Out-Null
    'PASS cancel selection returns home without scanning'
    $log=[ReportSmoke]::ChildByClass($main,'Edit')
    if ([ReportSmoke]::GetWindowLong($log,-16) -band 0x10000000) {throw 'Log should start collapsed'}
    [ReportSmoke]::PostMessage($main,0x111,[IntPtr]110,[IntPtr]::Zero) | Out-Null
    Start-Sleep -Milliseconds 300
    if (-not ([ReportSmoke]::GetWindowLong($log,-16) -band 0x10000000)) {throw 'Log failed to expand'}
    Save-Window $main 'ui-main-expanded.png'
    [ReportSmoke]::PostMessage($main,0x111,[IntPtr]110,[IntPtr]::Zero) | Out-Null
    Start-Sleep -Milliseconds 300
    if ([ReportSmoke]::GetWindowLong($log,-16) -band 0x10000000) {throw 'Log failed to collapse'}
    'PASS operation log expands and collapses'
    [ReportSmoke]::PostMessage($main,0x10,[IntPtr]::Zero,[IntPtr]::Zero) | Out-Null
    if (-not $app.WaitForExit(5000) -or $app.ExitCode -ne 0) {throw 'Application did not exit normally'}
    'PASS actual release EXE closes normally; no real scan or cleanup executed'
} finally {if (-not $app.HasExited) {$app.Kill();$app.WaitForExit()}}
