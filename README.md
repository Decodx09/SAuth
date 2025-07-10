# SAuth Summary

# 🔐 Authentication & User Management API

A **secure**, **feature-rich**, and **scalable** RESTful API built to handle user authentication, authorization, and account management with a focus on best practices like token security, validation, and role-based access control.

---

## ✨ Features Overview

### 🔑 Authentication

* **User Registration** (`/register`)
  Input validation, rate limiting, and email capture for secure onboarding.

* **User Login** (`/login`)
  Secure login with rate limiting to prevent brute-force attacks.

* **Refresh Tokens** (`/refresh-token`)
  Token-based session persistence and renewal without re-authentication.

* **Email Verification** (`/verify-email`)
  Email confirmation with support for resending verification links.

---

### 🛠️ Account Recovery

* **Forgot Password** (`/forgot-password`)
  Secure endpoint to trigger password reset flow.

* **Reset Password** (`/reset-password`)
  Token-based flow allowing users to safely set a new password.

---

### 👤 User Account Management *(Authenticated)*

* **Logout (Single Session)** (`/logout`)
  Invalidate the current device’s session.

* **Logout All Sessions** (`/logout-all`)
  Invalidate all active sessions across devices.

* **Get & Update Profile** (`/profile`)
  Retrieve and update personal user information.

* **Change Password** (`/change-password`)
  Secure endpoint to update password from within the user settings.

* **Deactivate Account** (`/deactivate`)
  Temporarily disable user account access.

* **Reactivate Account** (`/activate`)
  Re-enable access to a previously deactivated account.

---

### 🛡️ Admin Functionality *(Role: Admin)*

* **Force Logout All Users** (`/logout-all-users`)
  Immediately revoke access for all active sessions across the platform.
