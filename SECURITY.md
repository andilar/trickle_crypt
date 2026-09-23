# Security policy

## Project status

`tricklecrypt` is experimental cryptographic software. It has not received an
independent security audit and must not be used to protect production data.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Report it privately
through GitHub's **Security** tab using a private vulnerability report. Include:

- the affected version or commit;
- the impact and the conditions needed to trigger it;
- a minimal reproducer or test vector, when possible; and
- whether the report or its details may be publicly credited.

If private vulnerability reporting is not enabled for the repository, contact
the repository owner privately before disclosing details.

No response or remediation time is promised while the project remains
experimental. Coordinated disclosure is requested so users can update before
technical details are published.

## Supported versions

There are currently no production-supported versions. Security fixes are made
on the default branch and may be included in later releases.

## Security prerequisites for users

- Never reuse a `NoncePrefix` with the same key.
- Treat successful decryption of a non-final record as provisional stream data.
- Reject a stream that ends before an authenticated final record.
- Keep keys and plaintext out of logs and crash reports.
- Use independent keys when the same device key would otherwise cross protocol
  or application boundaries.

