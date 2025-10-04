# API Documentation

## Base URL
```
http://localhost:3000
```

## Authentication
API ใช้ JWT token สำหรับการ authentication โดยส่ง token ใน header:
```
Authorization: Bearer <your_jwt_token>
```

## Resell Users API

### 1. Signup
สร้างผู้ใช้ใหม่ในระบบ resell

**Endpoint:** `POST /api/resell/signup`

**Request Body:**
```json
{
  "username": "string (required)",
  "password": "string (required)",
  "email": "string (optional)",
  "role": "string (optional, default: 'user')"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User created successfully",
  "data": {
    "user_id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "role": "user"
  }
}
```

### 2. Login
เข้าสู่ระบบและรับ JWT token

**Endpoint:** `POST /api/resell/login`

**Request Body:**
```json
{
  "username": "string (required)",
  "password": "string (required)"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "user_id": 1,
      "username": "testuser",
      "email": "test@example.com",
      "role": "user",
      "balance": "0.00"
    }
  }
}
```

### 3. Get Profile
ดูข้อมูลโปรไฟล์ของผู้ใช้ (ต้องมี authentication)

**Endpoint:** `GET /api/resell/myprofile`

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "success": true,
  "message": "Profile retrieved successfully",
  "data": {
    "user_id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "role": "user",
    "balance": "0.00",
    "created_at": "2024-01-01T00:00:00.000Z"
  }
}
```

### 4. Purchase Site
ซื้อ site ใหม่ (ต้องมี authentication)

**Endpoint:** `POST /api/resell/purchase-site`

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "website_name": "string (required)",
  "admin_user": "string (required)",
  "admin_password": "string (required)"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Site purchased successfully",
  "data": {
    "customer_id": "3",
    "website_name": "newsite",
    "admin_user": "admin",
    "expiredDay": "2024-12-02",
    "amount_deducted": 100.00,
    "remaining_balance": 50.00
  }
}
```

### 5. Get Transaction History
ดูประวัติการทำธุรกรรม (ต้องมี authentication)

**Endpoint:** `GET /api/resell/transactions`

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "success": true,
  "message": "Transaction history retrieved successfully",
  "data": [
    {
      "transac_id": 1,
      "type": "purchase",
      "amount": "100.00",
      "description": "newsite;admin:password123",
      "status": "success",
      "created_at": "2024-01-01T00:00:00.000Z"
    }
  ]
}
```

### 6. Get Topup History
ดูประวัติการเติมเงิน (ต้องมี authentication)

**Endpoint:** `GET /api/resell/topup-history`

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "success": true,
  "message": "Topup history retrieved successfully",
  "data": [
    {
      "topup_id": 1,
      "method": "bank",
      "amount": "500.00",
      "slip_url": "https://example.com/slip.jpg",
      "status": "pending",
      "created_at": "2024-01-01T00:00:00.000Z"
    }
  ]
}
```

### 7. Submit Topup Request
ส่งคำขอเติมเงิน (ต้องมี authentication)

**Endpoint:** `POST /api/resell/topup`

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "method": "string (required: bank|wallet|card)",
  "amount": "number (required)",
  "slip_url": "string (optional)"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Topup request submitted successfully",
  "data": {
    "topup_id": 1,
    "method": "bank",
    "amount": 500.00,
    "slip_url": "https://example.com/slip.jpg",
    "status": "pending"
  }
}
```

## Auth Sites API

### 1. Get All Auth Sites
ดูรายการ auth sites ทั้งหมด

**Endpoint:** `GET /api/auth-sites`

**Response:**
```json
{
  "success": true,
  "message": "Auth sites retrieved successfully",
  "data": [
    {
      "id": 1,
      "customer_id": "1",
      "website_name": "model1",
      "admin_user": "admin",
      "expiredDay": "2025-10-22",
      "created_at": "2024-10-01T11:08:56.000Z"
    }
  ]
}
```

### 2. Get Auth Site by Customer ID
ดูข้อมูล auth site ตาม customer_id

**Endpoint:** `GET /api/auth-sites/:customer_id`

**Response:**
```json
{
  "success": true,
  "message": "Auth site retrieved successfully",
  "data": {
    "id": 1,
    "customer_id": "1",
    "website_name": "model1",
    "admin_user": "admin",
    "expiredDay": "2025-10-22",
    "created_at": "2024-10-01T11:08:56.000Z"
  }
}
```

### 3. Create Auth Site
สร้าง auth site ใหม่

**Endpoint:** `POST /api/auth-sites`

**Request Body:**
```json
{
  "customer_id": "string (required)",
  "website_name": "string (required)",
  "admin_user": "string (required)",
  "admin_password": "string (required)",
  "expiredDay": "string (required, format: YYYY-MM-DD)"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Auth site created successfully",
  "data": {
    "id": 3,
    "customer_id": "3",
    "website_name": "newsite",
    "admin_user": "admin",
    "expiredDay": "2025-12-31"
  }
}
```

## Error Responses

### 400 Bad Request
```json
{
  "success": false,
  "message": "Username and password are required"
}
```

### 401 Unauthorized
```json
{
  "success": false,
  "message": "Invalid username or password"
}
```

### 403 Forbidden
```json
{
  "success": false,
  "message": "Invalid or expired token"
}
```

### 404 Not Found
```json
{
  "success": false,
  "message": "User not found"
}
```

### 409 Conflict
```json
{
  "success": false,
  "message": "Username already exists"
}
```

### 500 Internal Server Error
```json
{
  "success": false,
  "message": "Internal server error",
  "error": "Error details"
}
```

## Testing the API

### 1. Test Database Connection
```bash
curl http://localhost:3000/test-db
```

### 2. Health Check
```bash
curl http://localhost:3000/health
```

### 3. Signup Example
```bash
curl -X POST http://localhost:3000/api/resell/signup \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123",
    "email": "test@example.com"
  }'
```

### 4. Login Example
```bash
curl -X POST http://localhost:3000/api/resell/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

### 5. Get Profile Example
```bash
curl -X GET http://localhost:3000/api/resell/myprofile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 6. Purchase Site Example
```bash
curl -X POST http://localhost:3000/api/resell/purchase-site \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "website_name": "newsite",
    "admin_user": "admin",
    "admin_password": "password123"
  }'
```

### 7. Get Transaction History Example
```bash
curl -X GET http://localhost:3000/api/resell/transactions \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 8. Submit Topup Request Example
```bash
curl -X POST http://localhost:3000/api/resell/topup \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "bank",
    "amount": 500,
    "slip_url": "https://example.com/slip.jpg"
  }'
```

## JWT Secret
```
91bbc8a7d1dab1b0604d9b91c89f2646
```

## Database Tables Used
- `resell_users` - ข้อมูลผู้ใช้ในระบบ resell
- `auth_sites` - ข้อมูลเว็บไซต์ที่ได้รับอนุญาต
