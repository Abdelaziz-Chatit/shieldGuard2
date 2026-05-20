# ShieldGuard Electron Frontend

## Setup

1. Install dependencies:
   ```
   npm install
   ```

2. Ensure the FastAPI backend is running on http://127.0.0.1:8000

3. For DNS blocking (optional, requires admin):
   - This repository previously included helper scripts for DNS and blocked-page serving, but those files have been removed.
   - Use your own DNS/blocking setup if needed.

## Running the App

```
npm start
```

## Features

- Login with admin/admin123
- Admin: Manage users, scans, whitelist requests
- User: Scans, phishing prediction
- DNS lookup test

## Testing

1. Login
2. Test scans by selecting directory/file
3. Test DNS lookup with "anydesk.com" (should show blocked)
4. For full browser blocking: Change DNS, browse to anydesk.com