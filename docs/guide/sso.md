# Single Sign-On

Single sign-on (SSO) lets the people in your organization sign in to OpenSCM
through your own identity provider — Microsoft Entra ID, Google Workspace, Okta,
Auth0, Keycloak, or any other provider that speaks **OpenID Connect**.

!!! info "Availability"
    Single sign-on is available in **OpenSCM SaaS**. It is not offered in
    Community Edition, which can authenticate against your own
    [LDAP directory](directories.md) instead.

---

## What it does, and what it does not

SSO answers one question: *is this person who they say they are?* Your provider
answers it, and OpenSCM signs in the matching user.

- **It does not create accounts.** Someone your provider vouches for who has no
  OpenSCM user is turned away. An administrator creates each user in OpenSCM
  first, as today, and chooses their role there.
- **It does not assign or change roles.** Roles stay in OpenSCM.
- **Passwords keep working.** SSO is an additional way in, not a replacement,
  so a mistyped issuer or an expired client secret cannot lock your
  organization out of its own account.

---

## Setting it up

You need the **Admin** role in OpenSCM, and the ability to register an
application at your provider.

### 1. Register OpenSCM at your provider

In your provider's admin console, create a new application of the kind it calls
a **web application** (or "confidential client") using **OpenID Connect**.

Give it this **redirect URI** — the page **Settings → Single Sign-On** shows the
exact value to copy:

```
https://<your OpenSCM address>/auth/sso/callback
```

The provider then gives you three things. Keep them for the next step.

| | What it is | Typically looks like |
|---|---|---|
| **Issuer URL** | The provider's own address for your directory — *not* its sign-in page | `https://login.microsoftonline.com/<directory-id>/v2.0` (Entra ID)<br>`https://accounts.google.com` (Google)<br>`https://<your-domain>.okta.com` (Okta)<br>`https://<host>/realms/<realm>` (Keycloak) |
| **Client ID** | The application's identifier | a UUID or a short string |
| **Client secret** | The application's password | a long random string |

The application must be allowed to request the `openid`, `email` and `profile`
scopes, and to use the **authorization code** flow.

!!! warning "Your provider must send a verified email address"
    The first time someone signs in, OpenSCM finds their account by **email
    address**, and only trusts an address the provider marks as **verified**
    (the `email_verified` claim). Without it the sign-in is refused — see
    [The first sign-in](#the-first-sign-in) and
    [Troubleshooting](#troubleshooting).

    Check that your provider sends both `email` and `email_verified` in the ID
    token. Some do not by default. Microsoft Entra ID in particular does not
    include `email_verified` in its default ID token.

### 2. Enter it in OpenSCM

Go to **Settings → Single Sign-On**.

| Field | |
|---|---|
| **Display name** | A name for your own reference, such as "Acme Entra ID" |
| **Issuer URL** | From your provider. Must be an `https://` address reachable from the internet |
| **Client ID** | From your provider |
| **Client secret** | From your provider. It is stored and never shown again; leave the field blank on later edits to keep it |

Click **Save**. This stores the provider without switching it on.

### 3. Test, then enable

Click **Test connection**. OpenSCM contacts the provider and reports what it
found, or exactly what is wrong — a wrong Issuer URL is otherwise invisible
until someone cannot sign in, and that someone is not the person who typed it.

When the test passes, tick **Enable single sign-on** and **Save**. OpenSCM
contacts the provider once more and only switches SSO on if it answers
correctly.

!!! note "The App URL must be set"
    The redirect URI is built from the installation's **App URL**. If the page
    says it is not set, SSO cannot be enabled until the platform operator sets
    it.

---

## Signing in

On the sign-in page, below the password form, enter your **Organization** and
click **Sign in with SSO**. You are sent to your provider, sign in there as you
normally do, and come back signed in to OpenSCM.

A session started this way is an ordinary OpenSCM session: it lasts the same
8 hours and follows the same rules as one started with a password (see
[Session Management](admin.md#session-management)).

### The first sign-in

The first time a person signs in through SSO, OpenSCM has to work out which of
its users they are. It looks for the **one** user in your organization whose
email address matches the verified address from your provider (letter case does
not matter), and **links** that user to the person's identity at the provider.

From then on they are recognized by that link, not by email — so a later change
of address at the provider does not affect them.

The sign-in is refused, and nothing is linked, when:

- no user in your organization has that email address;
- the provider does not say the address is verified;
- **two or more** users share that address — OpenSCM will not guess. Give each
  user a distinct email address in OpenSCM;
- the only user with that address is already linked to a different identity.

---

## Managing linked users

### Seeing who is linked

Open a user from **Settings → Users**. A linked user's page shows a
**Single sign-on** card.

### Unlinking a user

If the wrong person was linked — a recycled email address, a typo on the
account — open the user and click **Unlink** (Admin role). This:

- removes the link, and
- signs that user out everywhere, since one of their sessions may be the wrong
  person's. If you unlink **your own** account, the browser you are using stays
  signed in.

The next SSO sign-in with a matching verified email links the account again, by
the same rules as a first sign-in. Correct the user's email address first if it
was the cause.

### Removing someone's access

!!! danger "Removing a user at your provider is not a full removal"
    Taking someone out of your provider stops them signing in **through it**.
    It does not:

    - end a session they already have open (sessions last up to 8 hours), or
    - stop them signing in with their OpenSCM **password**.

    To remove someone's access completely, **delete their user in OpenSCM**
    (Settings → Users). That ends their sessions immediately.

---

## Turning it off

**Settings → Single Sign-On → Disable** switches SSO off and keeps the
configuration, so it can be enabled again later. Everyone signs in with their
password while it is off. Existing sessions and links are not affected.

---

## Troubleshooting

The sign-in page shows a short message. The **specific reason** for a failed
sign-in is recorded in **Settings → Audit Log**, as a `auth.login_failure`
entry whose details begin with `sso:`.

| The sign-in page says | Likely cause | What to do |
|---|---|---|
| *Single sign-on is not set up for this organization.* | The organization name was mistyped, or SSO is not enabled | Check the name; an admin checks **Settings → Single Sign-On** shows **Enabled** |
| *Your provider signed you in, but there is no OpenSCM account for you…* | No user matches (see [The first sign-in](#the-first-sign-in)) | An admin creates the user, or corrects their email address. If the audit log says the provider *has not verified the email*, configure your provider to send `email_verified` |
| *Sign-in was cancelled or refused at your provider.* | You cancelled, or you are not assigned to the application at the provider | Ask your provider's administrator to assign you to it |
| *Single sign-on did not complete…* | Anything else — read the audit log entry | See below |
| *This organization is suspended.* | The organization is suspended | Contact support |

Common audit-log reasons behind *did not complete*:

| Audit log details | Meaning |
|---|---|
| `token endpoint answered HTTP 401` | The client secret is wrong or has expired. Enter the current one and save |
| `discovery failed: …` | The provider could not be reached, or the Issuer URL is wrong. Use **Test connection** |
| `token rejected: InvalidAudience` | The Client ID does not match the application the provider issued the token for |
| `token rejected: InvalidIssuer` | The Issuer URL is not exactly the provider's issuer |
| `token rejected: ExpiredSignature` | The provider's clock and the server's differ by more than a minute, or the sign-in took too long |
| `state expired` | The sign-in took more than 10 minutes. Start again |
| `… users share this email; refusing to guess` | Two users have the same email address |

If *did not complete* appears and **nothing** is recorded in the audit log, the
return from the provider did not belong to a sign-in this browser had started:
the link was opened a second time, opened in a different browser, or cookies
are blocked for the OpenSCM site. Start again from the sign-in page, in one
browser, with cookies allowed.

If **Test connection** fails:

| Message | Meaning |
|---|---|
| *did not return an OpenID Connect discovery document* | The Issuer URL points at something else — often the provider's sign-in page. Use the issuer |
| *names a different issuer* | The Issuer URL must match the provider's issuer exactly; copy it from the provider |
| *is not a public address* / *must use https* | The provider must be reachable from the internet over `https://` |
| *signs tokens with … which this server cannot verify* | The provider must sign ID tokens with RS256, PS256, ES256, ES384 or EdDSA (or their stronger variants). Shared-secret signing (HS256) is not accepted |

---

## How it is protected

For those reviewing the integration:

- **OpenID Connect authorization-code flow with PKCE.** Tokens are exchanged
  server-to-server; none pass through the browser's address bar.
- **Every ID token is verified**: its signature against the keys your provider
  publishes, that it was issued by *your* provider, for *this* application, has
  not expired, and belongs to this particular sign-in.
- **Each sign-in is single-use and tied to the browser that started it**, and
  must be completed within 10 minutes.
- **An identity only ever matches a user in your own organization.**
- **The client secret is never shown again** after you save it.
- **Sign-ins and failures are recorded** in the audit log, as are changes to
  the configuration and every unlink.

---

## Not supported

- **SAML.** OpenID Connect only.
- **Automatic user creation**, and mapping provider groups to OpenSCM roles.
- **More than one provider** per organization.
- **Starting from the provider's app launcher** ("IdP-initiated" sign-in). Start
  from the OpenSCM sign-in page.
- **Requiring SSO** — passwords cannot be switched off.
