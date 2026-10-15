param (
    [string]$PcapFile = "",
    [string]$MaxPackets = ""
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Detect project directory
if (Test-Path "$ScriptDir\src\main\java\com\packetanalyzer\Main.java") {
    $ProjDir = "$ScriptDir"
} elseif (Test-Path "$ScriptDir\deep_packet_inspection-main\src\main\java\com\packetanalyzer\Main.java") {
    $ProjDir = "$ScriptDir\deep_packet_inspection-main"
} else {
    Write-Error "Could not find project source directory."
    exit 1
}

# Default pcap file
if ([string]::IsNullOrWhiteSpace($PcapFile)) {
    $PcapFile = "$ProjDir\test_dpi.pcap"
}

# Generate pcap if missing
if (-not (Test-Path $PcapFile) -and (Test-Path "$ProjDir\generate_test_pcap.py")) {
    Write-Host "[INFO] Generating test PCAP file..." -ForegroundColor Cyan
    python "$ProjDir\generate_test_pcap.py"
}

Write-Host "======================================================================" -ForegroundColor Green
Write-Host "   Deep Packet Inspection (DPI) & Packet Analyzer Launcher" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""

# Compile
Write-Host "[INFO] Compiling Java DPI Analyzer..." -ForegroundColor Cyan
javac -d "$ProjDir\src\main\java" (Get-Item "$ProjDir\src\main\java\com\packetanalyzer\*.java" | ForEach-Object { $_.FullName })
if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilation failed."
    exit $LASTEXITCODE
}

# Run
Write-Host "[INFO] Running Deep Packet Inspection on $PcapFile..." -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""

if ([string]::IsNullOrWhiteSpace($MaxPackets)) {
    java -cp "$ProjDir\src\main\java" com.packetanalyzer.Main "$PcapFile"
} else {
    java -cp "$ProjDir\src\main\java" com.packetanalyzer.Main "$PcapFile" $MaxPackets
}
