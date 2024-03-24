# Description

> Rum runners left only this strange signature. Please find out how they bypassed the authentication.

## Vulnerability
Non-unique representation: authenticatedAttributes is hashed if authenticatedAttributes is present, but content is hashed as-is if authenticatedAttributes is not present.

## Solution.
Transpose authenticatedAttributes to content by tampering with the given sign.der, where authenticatedAttributes first byte `0xa0` (IMPLICIT [0]) -> content first byte `0x31` (SET OF), second byte to end is the same, thus creating valid input

- **Flag: `LINECTF{2267fae1b822213bd9a1525763b58146}`**
