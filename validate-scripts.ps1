$scripts = Get-ChildItem -Path ".\scripts" -Filter "*.ps1" -Recurse
foreach ($script in $scripts) {
    $content = Get-Content $script.FullName -Raw
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors) {
        Write-Host "Syntax error in $($script.Name)" -ForegroundColor Red
        $parseErrors | ForEach-Object { Write-Host $_ }
    }
    else {
        Write-Host "$($script.Name) is valid" -ForegroundColor Green
    }
}
$scripts = Get-ChildItem -Path ".\scripts" -Filter "*.ps1" -Recurse
foreach ($script in $scripts) {
    $content = Get-Content $script.FullName -Raw
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors) {
        Write-Host "Syntax error in $($script.Name)" -ForegroundColor Red
        $parseErrors | ForEach-Object { Write-Host $_ }
    }
    else {
        Write-Host "$($script.Name) is valid" -ForegroundColor Green
    }
}
