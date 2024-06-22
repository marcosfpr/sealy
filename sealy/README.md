# sealy

`sealy` is a crate that wraps the [Microsoft SEAL](https://github.com/microsoft/SEAL)
library to enable us to perform arithimetic operations over encrypted data. It is a fork
of the Sunscreen's SEAL bindings that you can found [here](https://github.com/Sunscreen-tech/Sunscreen).

In the context of Federated Learning, this crate enables us to homomorphically aggregate
encrypted gradients comming from different nodes in the federated network.

## Architecture

All types in this crate implement Sync/Send. So long as you never dereference the
internal handle on any type after it has been dropped, these traits
should safely hold. The internal handles should be of little use to you anyways.

This crate currently incomplete (e.g. CKKS is not currently supported).
