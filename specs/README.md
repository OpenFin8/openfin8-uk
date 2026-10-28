# OpenFin8:UK - Upstream Specification References

**The Open Banking Standard may be vendored - with the notice.**

The Open Banking Standard (the Read/Write API specifications) is
published by Open Banking Limited under the **MIT Open Licence**
(<https://www.openbanking.org.uk/open-licence>). Unlike the FDX
adapters in this family, this repository MAY include Open Banking
Standard material (the OB resource paths in the published
`docs/openapi.json`) provided the OBL copyright notice is preserved
- the CI drift guard enforces exactly that.

What this directory is for: **optional local reference copies** of
the upstream OBL swagger bundles, gitignored so the repository does
not drift from the published standard (which OBL versions
independently):

```
specs/ob/3.1.11/          # your local copy of the OBL R/W API 3.1.11 swagger files
specs/ob/4.0.1/           # ...and for 4.0.1, if you serve it
```

Operators download these from
<https://standards.openbanking.org.uk/api-specifications/> and point
conformance tooling at them. Nothing in this service reads them at
runtime - the served surface is configured via
`OPENFIN8_UK_VERSION` (default `3.1.11`).

For the FDX (US/CA) adapters the policy is the opposite: the FDX
API specification is licensed under the FDX API License Agreement
and must never be committed - see the
[`bank8-open-us`](../bank8-open-us) and
[`bank8-open-ca`](../bank8-open-ca) repositories.