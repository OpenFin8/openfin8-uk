# OpenFin8:UK - Business Requirements & Functionality

> The OBL Read/Write API ASPSP adapter. This BRD records the business
> scope the adapter delivers; section 9 lists the acceptance criteria.
>
> Audience: product owners, business analysts, and anyone evaluating what
> the UK adapter **does for the business**. For architecture read
> `README.md`; for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

OpenFin8:UK is **UK open banking**: the Open Banking Limited (OBL)
Read/Write API ASPSP surface (v3.1.x, v4.0.1 configurable) serving
Account Information Service Providers (AISPs), Payment Initiation
Service Providers (PISPs), and Card-Based Payment Instrument Issuers
(CBPIIs). It delivers:

- **A mandated-compliance surface** - UK open banking is required
  (CMA order for the CMA9 + PSD2/FCA rules for all ASPSPs): this
  service is the compliance boundary for a UK institution, honoring
  the OBL wire contract exactly (envelopes, error semantics,
  availability).
- **The intent-based consent model** - TPPs stage consent resources
  (account-access, domestic-payment, VRP, funds-confirmation) via
  `client_credentials`; customers authorize intents; tokens bind to
  intents - a materially different ceremony from FDX, delivered over
  the same kernel.
- **Payments for TPPs** - domestic payments, domestic VRP (sweeping
  first), scheduled payments, standing orders, and file payments
  through the same one-executor model (bank8:Payments).
- **The FAPI-grade security posture** - hybrid-flow ceremony,
  detached JWS request/response signing, OB Directory trust - the
  security model UK TPPs and the FCA expect.

## 2. Business Scope (What the Service Will Provide)

| # | Capability area | What the business gets |
|---|---|---|
| 1 | AIS surfaces (aisp) | Account-access consents; accounts, balances, transactions, beneficiaries, direct debbits, standing orders, scheduled payments, statements, parties, products, offers |
| 2 | PIS surfaces (pisp) | Domestic payment consents + payments, scheduled payments, standing orders, file payments (pain.001), VRP (consents + sweeping) |
| 3 | CBPII surfaces (cbpii) | Funds-confirmation consents + funds confirmations |
| 4 | Consent lifecycle | Intent staging (`awaiting_authorization`), PSU authorization, the four-state OB consent model, TPP + PSU revocation, 24h staged-intent expiry |
| 5 | OBL semantics | `{Data, Links, Meta}` envelopes, conditional-field exclusion, 400-vs-404 error rules, `x-idempotency-key` discipline, pagination links |
| 6 | Signing | Detached JWS request verification + mandatory payment-response signing (PS256, OB Directory JOSE claims) |
| 7 | Event notifications | The OBL event-notification API (JWS-signed payloads; webhook + aggregated-polling modes) over the kernel's worker |
| 8 | Discovery | The served-version + role matrix for admin; the AS's openid-configuration remains the TPP discovery point |
| 9 | Admin console | The kernel pages under the UK identity (consents, recipients, settings) |
| 10 | Events | Family `openfin8:uk:*` |

**What the adapter will NOT own (business boundary):**

| Out of scope | Owned by |
|---|---|
| Consent ledger, registry, CSDF, notifications (the implementation) | openfin8-core (shared with CA/US) |
| Account/transaction data | bank8:Ledger (public API only) |
| Money-movement execution | bank8:Payments |
| The FAPI ceremony hosting | Sentin8:Auth (gains the FAPI 1 Advanced profile alongside this adapter) |
| The CA/US surfaces | Their adapters (profile isolation) |

## 3. Business Capabilities

### 3.1 The intent-based consent ceremony

Unlike FDX's consent-object flow, OBL stages an **intent**: the TPP
creates the consent resource with a client-credentials token (TPP
identification only), the PSU authorizes the intent through the
bank's authorization flow (FAPI hybrid: `code id_token` with the
intent bound into the request object), and the issued access token
is bound to that intent. Data calls resolve consent by intent id -
the same no-consent-no-data chokepoint, with intent as the join key.

### 3.2 The UK wire contract

The OBL Read/Write Data API Profile rules the adapter must honor
exactly: the role-segmented paths
(`/open-banking/v{maj}.{min}/{aisp|pisp|cbpii}/...`), the response
envelopes with absolute self-links, the error model (`OBErrorResponse1`
with OB error codes; unknown resource id → 400, unimplemented
resource → 404, empty lists → 200-with-empty-array), and the
idempotency-key discipline on payment creation.

### 3.3 The specification-licensing difference

Unlike the FDX adapters, **the OBL specifications are MIT Open
Licensed** - this adapter may publish the OB resource paths in its
published spec with the OBL copyright notice preserved (the
drift-guard inverts: it asserts the notice IS present). UK TPPs get a
complete published reference.

## 4. Business Events (Outbound)

Family `openfin8:uk:*`: consent lifecycle, payment lifecycles, VRP
events - plus the OBL event-notification surface layered on the
kernel's delivery worker.

## 5. Business Rules & Invariants

- Every kernel invariant holds (consent chokepoint, terminal
  revocation, fail-closed minimization, tenant discipline).
- Every payment initiation verifies the `x-jws-signature` and signs
  its response; the intent-to-token binding is verified at the
  middleware.
- VRP executions enforce the consent's control parameters (max
  amount, periodic limits) at initiation time.
- Directory JWKS unavailability fails closed (503), never skip-verify.
- Version selection: `OPENFIN8_UK_VERSION` (default 3.1.11),
  per-environment.

## 6. Target-User Roles & Use Cases

| Role | Use case |
|---|---|
| UK bank (ASPSP) | Enable `openfin8:uk`; serve the OBL surface; honor the CMA/PSD2 obligations |
| TPP (AISP/PISP/CBPII) | Register with the OB Directory, stage consents, run PSU journeys, consume consented data / initiate payments |
| Bank customer (PSU) | Authorizes intents on the bank's approval screens; revokes via bank channels |
| FCA / OBL conformance | The OBL conformance suite runs against the adapter (the certification path) |

## 7. KPIs / Success Criteria

- **Conformance**: the official OBL conformance tooling passes
  (account information + payment initiation profiles).
- **Wire-exactness**: the envelope/error semantics verified by
  fixture tests per the OBL profile rules.
- **Market entry cost**: same Profile guarantee as CA/US - enrollment
  + configuration.

## 8. Dependencies & Reliance on Other Services

The kernel + platform set (as CA/US), plus two UK-specific
integrations: **Sentin8:Auth gains the FAPI 1 Advanced profile flag**
(hybrid flow, request objects, `private_key_jwt` client auth) and the
**OB Directory** (JWKS trust anchors, software-statement assertions
in DCR - a mock directory mode drives dev/e2e).

## 9. Acceptance Criteria (the implementation's definition of done)

- The publication guard passes (the vendored OBL notice asserted in
  the published spec).
- The intent consent state machine over the kernel's
  `awaiting_authorization` + `intent_payload`, with the staged
  intent expiry sweep: the four-state OB machine, the
  client-credentials staging, the authorization observation, the
  revocation→400 rule, and the declared 24h sweep schedule.
- The FAPI ceremony + the JWS sign/verify: the JOSE-header
  validation, the fail-closed verdicts (Directory down → 503, never
  skip-verify), the DCR body with the SSA, the hybrid request-object
  shape, and the deterministic sign/verify; the Auth FAPI-profile
  drive + the real Directory JWKS are the platform/production halves.
- The envelope codec round-trips (conditional exclusion, empty-array,
  pagination); the 400-vs-404 fixture suite passes: the
  `{Data, Risk, Links, Meta}` codec + `OBErrorResponse1` + the OBL
  error rules.
- The e2e journey drives the UK AISP flow + the PISP domestic-payment
  flow (`openfin8_uk_ob_journey.spec.ts`: the intent staging, the
  envelope assertions, the revocation→400 verdict, the JWS +
  idempotency gates, the honest 404s); the browser FAPI PSU page is
  the recipient-app story.
- AIS/PIS/CBPII behind the intent chokepoint: the aisp reads (the
  Ledger lane), the domestic payments + VRP with the
  control-parameter enforcement, the cbpii funds confirmations, and
  the OBL event notifications; file payments answer the honest 404
  (the decided follow-on); the published spec + drift guard + the
  site dossier.

## 10. Open Business Questions

- Where does the OBL conformance suite run operationally (CI nightly
  vs pre-release manual)?
- Does the staged-intent expiry sweep generalize into the kernel, or
  stay UK-owned until a second standard needs it?
- VRP non-sweeping (`vrp-extended`): in scope for the first release,
  or is the `vrp-basic` sweeping profile the v1 boundary?
- File payments (pain.001 batches): first release or follow-on given
  the Payments file pipeline exists?

---

**Architecture & Design:** openfin8:uk and its underlying concepts were
designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).