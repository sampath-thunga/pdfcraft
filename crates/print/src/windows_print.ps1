# Print a print-ready PDF on Windows (issue #756). The job arrives in PDFCRAFT_* environment
# variables, never as arguments: printer names contain spaces and quotes, and the document's
# path must not be visible in the process list while it prints.
#
# The in-box Windows.Data.Pdf renders each sheet at the printer's own resolution and
# System.Drawing.Printing spools it with the driver's settings — copies, collation, duplex and
# colour reach the spooler as the job's, the way `lp -o` sends them on CUPS. No PDF reader is
# needed, and the calling code touches no Win32 API.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Runtime.WindowsRuntime
try {
    $null = [Windows.Data.Pdf.PdfDocument, Windows.Data.Pdf, ContentType = WindowsRuntime]
} catch {
    throw 'this Windows installation cannot render PDFs: the Windows.Data.Pdf component is missing'
}
$null = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]

# Await the WinRT asynchronous APIs from .NET Framework's PowerShell.
$opTask = [System.WindowsRuntimeSystemExtensions]::GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
} | Select-Object -First 1
$actTask = [System.WindowsRuntimeSystemExtensions]::GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction'
} | Select-Object -First 1
function AwaitOp($operation, $resultType) {
    $task = $opTask.MakeGenericMethod($resultType).Invoke($null, @($operation))
    $task.Wait()
    $task.Result
}
function AwaitAct($action) {
    $task = $actTask.Invoke($null, @($action))
    $task.Wait()
}

$source = AwaitOp ([Windows.Storage.StorageFile]::GetFileFromPathAsync($env:PDFCRAFT_PRINT_FILE)) ([Windows.Storage.StorageFile])
$document = AwaitOp ([Windows.Data.Pdf.PdfDocument]::LoadFromFileAsync($source)) ([Windows.Data.Pdf.PdfDocument])
if ($document.PageCount -lt 1) { throw 'the print-ready PDF has no pages' }

$printer = [System.Drawing.Printing.PrintDocument]::new()
$printer.DocumentName = $env:PDFCRAFT_PRINT_TITLE
$settings = $printer.PrinterSettings
if ($env:PDFCRAFT_PRINT_PRINTER) {
    try {
        $settings.PrinterName = $env:PDFCRAFT_PRINT_PRINTER
    } catch {
        throw ('the printer is not available: ' + $env:PDFCRAFT_PRINT_PRINTER)
    }
}
$settings.Copies = [Math]::Min(32767, [Math]::Max(1, [int]$env:PDFCRAFT_PRINT_COPIES))
$settings.Collate = ($env:PDFCRAFT_PRINT_COLLATE -eq '1')
$settings.Duplex = switch ($env:PDFCRAFT_PRINT_DUPLEX) {
    'long-edge' { [System.Drawing.Printing.Duplex]::Horizontal }
    'short-edge' { [System.Drawing.Printing.Duplex]::Vertical }
    default { [System.Drawing.Printing.Duplex]::Simplex }
}
if ($env:PDFCRAFT_PRINT_GRAYSCALE -eq '1') { $printer.DefaultPageSettings.Color = $false }

# One sheet at a time: its page is rendered when the driver asks for it, so a long document
# holds only one page's bitmap in memory.
$script:sheets = 0
$printer.add_PrintPage({
    param($sender, $e)
    if ($script:sheets -ge $document.PageCount) { $e.HasMorePages = $false; return }
    $page = $document.GetPage($script:sheets)
    $stream = $null
    $bitmap = $null
    try {
        # The sheet's area is in hundredths of an inch, a page's size in 1/96-inch units, and the
        # driver's resolution in dots per inch: fit the page into the printable area, centred.
        $area = $e.MarginBounds
        $w = $page.Size.Width
        $h = $page.Size.Height
        $scale = [Math]::Min($area.Width / 100.0 * 96.0 / $w, $area.Height / 100.0 * 96.0 / $h)
        $dpi = [Math]::Min(600, [Math]::Max(72, $e.Graphics.DpiX))
        $options = [Windows.Data.Pdf.PdfPageRenderOptions]::new()
        $options.DestinationWidth = [int][Math]::Ceiling($w * $scale * $dpi / 96.0)
        $options.DestinationHeight = [int][Math]::Ceiling($h * $scale * $dpi / 96.0)
        $stream = [System.IO.MemoryStream]::new()
        $random = [System.IO.WindowsRuntimeStreamExtensions]::AsRandomAccessStream($stream)
        AwaitAct ($page.RenderToStreamAsync($random, $options))
        $stream.Position = 0
        $bitmap = [System.Drawing.Image]::FromStream($stream)
        $drawW = $w * $scale / 96.0 * 100.0
        $drawH = $h * $scale / 96.0 * 100.0
        $box = [System.Drawing.RectangleF]::new($area.Left + ($area.Width - $drawW) / 2.0, $area.Top + ($area.Height - $drawH) / 2.0, $drawW, $drawH)
        $e.Graphics.DrawImage($bitmap, $box)
    } finally {
        if ($bitmap) { $bitmap.Dispose() }
        if ($stream) { $stream.Dispose() }
        $page.Dispose()
    }
    $script:sheets++
    $e.HasMorePages = ($script:sheets -lt $document.PageCount)
})
$printer.Print()
Write-Output ('spooled ' + $document.PageCount + ' sheet(s)')
