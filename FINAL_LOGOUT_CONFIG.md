# ✅ Final Logout Configuration

To fix the "Internal Server Error" loop AND ensure Single Sign-Out works, you must update the Keycloak configuration to use the new special listener endpoint.

### 1. Update Keycloak Settings ⚙️

1.  Go to **Keycloak Admin Console** > **Clients** > `localhost-8070-website-dinas-pendidikan`.
2.  Go to **Logout settings** (or Advanced tab).
3.  **Front-channel logout URL**: Set this to:
    ```
    http://localhost:8070/sso/logout-listener
    ```
    *(Note: Do NOT use `/logout`. Use `/sso/logout-listener`)*.
4.  **Front-channel logout session required**: Enable (On).
5.  Click **Save**.

### 2. How it Works Now 🔄

*   **User clicks Logout on Client:**
    *   Client clears local session.
    *   Client redirects to Keycloak (`/logout`).
    *   Keycloak terminates SSO session.
    *   Keycloak redirects back to Client Login page.
    *   **Result:** Clean logout, no loop.

*   **User clicks Logout on Portal SSO (or other app):**
    *   Keycloak sends a background request (or iframe) to `http://localhost:8070/sso/logout-listener`.
    *   Client receives request and clears local session.
    *   Client returns `200 OK` (does NOT redirect).
    *   **Result:** Client is logged out without user interaction.

### 3. Verify 🧪

1.  **Restart Server:** (Already done automatically).
2.  **Test 1 (Client Logout):** Login -> Click Logout. Should redirect to login page smoothly.
3.  **Test 2 (SSO Logout):** Login to Client -> Open Portal SSO (`localhost:3000`) -> Logout from Portal. -> Refresh Client page. You should be logged out.
