$env:PATH = "C:\Users\flori\.cargo\bin;" + $env:PATH
Set-Location "C:\Users\flori\Documents\oarn-network\oarn-node"
if ($args[0] -eq "check") {
    cargo check
} else {
    cargo build --release
}
