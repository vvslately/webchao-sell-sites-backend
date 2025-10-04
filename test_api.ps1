# Test API Script

Write-Host "Testing Resell API..." -ForegroundColor Green

# 1. Test Signup
Write-Host "`n1. Testing Signup..." -ForegroundColor Yellow
$signupBody = @{
    username = "testuser3"
    password = "password123"
    email = "test3@example.com"
} | ConvertTo-Json

try {
    $signupResponse = Invoke-RestMethod -Uri "http://localhost:3000/api/resell/signup" -Method POST -ContentType "application/json" -Body $signupBody
    Write-Host "Signup Success:" -ForegroundColor Green
    $signupResponse | ConvertTo-Json -Depth 3
} catch {
    Write-Host "Signup Error:" -ForegroundColor Red
    Write-Host $_.Exception.Message
}

# 2. Test Login
Write-Host "`n2. Testing Login..." -ForegroundColor Yellow
$loginBody = @{
    username = "testuser3"
    password = "password123"
} | ConvertTo-Json

try {
    $loginResponse = Invoke-RestMethod -Uri "http://localhost:3000/api/resell/login" -Method POST -ContentType "application/json" -Body $loginBody
    Write-Host "Login Success:" -ForegroundColor Green
    $loginResponse | ConvertTo-Json -Depth 3
    
    # Store token for next requests
    $token = $loginResponse.data.token
    Write-Host "`nToken: $token" -ForegroundColor Cyan
    
} catch {
    Write-Host "Login Error:" -ForegroundColor Red
    Write-Host $_.Exception.Message
}

# 3. Test Purchase Site (if login successful)
if ($token) {
    Write-Host "`n3. Testing Purchase Site..." -ForegroundColor Yellow
    $purchaseBody = @{
        website_name = "testsite"
        admin_user = "admin"
        admin_password = "admin123"
    } | ConvertTo-Json
    
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type" = "application/json"
    }
    
    try {
        $purchaseResponse = Invoke-RestMethod -Uri "http://localhost:3000/api/resell/purchase-site" -Method POST -Headers $headers -Body $purchaseBody
        Write-Host "Purchase Success:" -ForegroundColor Green
        $purchaseResponse | ConvertTo-Json -Depth 3
    } catch {
        Write-Host "Purchase Error:" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
    
    # 4. Test Get Profile
    Write-Host "`n4. Testing Get Profile..." -ForegroundColor Yellow
    try {
        $profileResponse = Invoke-RestMethod -Uri "http://localhost:3000/api/resell/myprofile" -Method GET -Headers $headers
        Write-Host "Profile Success:" -ForegroundColor Green
        $profileResponse | ConvertTo-Json -Depth 3
    } catch {
        Write-Host "Profile Error:" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
}

Write-Host "`nTest completed!" -ForegroundColor Green
