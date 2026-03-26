$env:PATH = "C:\Users\flori\.cargo\bin;" + $env:PATH
$env:RUST_LOG = "info"

$nodePath = "C:\Users\flori\Documents\oarn-network\oarn-node\target\release\oarn-node.exe"
$modelPath = "C:\Users\flori\.oarn\test\model.onnx"
$inputPath = "C:\Users\flori\.oarn\test\input.json"

Write-Host "Testing ONNX execution..."
Write-Host "Model: $modelPath"
Write-Host "Input: $inputPath"
Write-Host ""

# Run the inference test command
& $nodePath inference --model $modelPath --input $inputPath
