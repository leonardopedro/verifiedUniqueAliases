# verifiedUniqueAliases

Using Paypal's openid information about the verification and unique identifier, we can produce a zero knowledge proof (using RISC zero VM) that an encryption of the unique identifier is verified by Paypal. The encryption public key is chosen by the user, for instance a Police email encryption public key. We can create a function/service that verifies the zero-knowledge proof.

This is useful to implement a network of GNS/DISSENS servers, for online voting, for email aliases using https://addy.io, ads and analytics https://docs.prebid.org/identity/sharedid.html, etc.
