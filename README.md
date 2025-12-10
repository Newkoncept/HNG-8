# Wallet Service (HNG Internship Stage 8)

A FastAPI-based wallet system implementing: - Google Authentication
(OAuth2) - JWT session management - API Key authentication with
permission control - Wallet creation, balance retrieval, deposits,
transfers - Paystack payment integration (transaction initialization +
webhook crediting) - Complete transaction history tracking

------------------------------------------------------------------------

## 🚀 Features

### **Authentication**

-   Google OAuth login (`/auth/google`)
-   JWT-based user sessions
-   API Keys:
    -   Up to 5 per user
    -   Permissions: `read`, `deposit`, `transfer`
    -   Auto-expiry and revocation support

------------------------------------------------------------------------

## 💰 Wallet Operations

### 1. **Create Deposit**

`POST /wallet/deposit`

Starts a Paystack payment session.\
Returns a Paystack authorization URL + a unique transaction reference.

### 2. **Paystack Webhook**

`POST /wallet/paystack/webhook`

-   Validates Paystack signature\
-   Updates transaction status\
-   Credits wallet on successful payment\
-   **Idempotent** (no double-credit)

### 3. **Check Deposit Status**

`GET /wallet/deposit/{reference}/status`

### 4. **Wallet Balance**

`GET /wallet/balance`

### 5. **Wallet Transfer**

`POST /wallet/transfer`

Atomic transfer between wallets.

<!-- ### 6. **Transactions List**

`GET /wallet/transactions` -->

------------------------------------------------------------------------

## 🔐 API Key Format

    sk_live_<public_id>_<secret>

-   `public_id`: UUID4 hex\
-   `secret`: random 32+ byte token (hashed with bcrypt)\
-   Stored hashed in DB\
-   Verified per request via `x-api-key` header

------------------------------------------------------------------------

## 🛠️ Tech Stack

  Component     Technology
  ------------- ----------------------------------------
  Backend API   FastAPI
  DB            PostgreSQL
  ORM           SQLAlchemy + Alembic
  Auth          JWT, Google OAuth
  Payments      Paystack
  Security      bcrypt, HMAC-SHA512 webhook validation
  Server        Uvicorn

------------------------------------------------------------------------

## 📦 Project Structure (Simplified)

    app/
     ├── features/
     │   ├── auth/
     │   ├── api_keys/
     │   ├── wallet/
     │   ├── transaction/
     ├── database/
     ├── main.py
     └── ...

------------------------------------------------------------------------

## ⚙️ Environment Variables

Create a `.env` file:

    JWT_SECRET=<your-secret>
    GOOGLE_CLIENT_ID=<id>
    GOOGLE_CLIENT_SECRET=<secret>
    PAYSTACK_SECRET_KEY=sk_test_xxx
    PAYSTACK_WEBHOOK_SECRET=sk_test_xxx
    DATABASE_URL=postgresql://...

------------------------------------------------------------------------

## 💳 Setting up Paystack Webhook (Localhost)

Use `ngrok` or `cloudflared`:

    ngrok http 8000

Set webhook URL in Paystack dashboard:

    https://<ngrok-subdomain>/wallet/paystack/webhook

------------------------------------------------------------------------

## ▶️ Running Locally

**Install:**

    pip install -r requirements.txt

**Start server:**

    uvicorn app.main:app --reload

------------------------------------------------------------------------

## 🧪 Testing the Workflow

### Deposit Flow:

1.  `POST /wallet/deposit`
2.  Visit `authorization_url`
3.  Complete payment
4.  Paystack calls `/wallet/paystack/webhook`
5.  Check balance: `GET /wallet/balance`
6.  Check status: `GET /wallet/deposit/{reference}/status`

------------------------------------------------------------------------

------------------------------------------------------------------------

## 👨‍💻 Author
Taiwo Oluwagbemiga
HNG Internship (Stage 8 Wallet API Task)
