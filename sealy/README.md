# sealy

`sealy` is a crate that wraps the [Microsoft SEAL](https://github.com/microsoft/SEAL)
library to enable us to perform arithimetic operations over encrypted data. It is a fork
of the Sunscreen's SEAL bindings that you can found [here](https://github.com/Sunscreen-tech/Sunscreen).

## Architecture

All types in this crate implement Sync/Send. So long as you never dereference the
internal handle on any type after it has been dropped, these traits
should safely hold. The internal handles should be of little use to you anyways.

Schemes implemented:

* Brakerski/Fan-Vercauteren (BFV)
* Cheon-Kim-Kim-Song (CKKS)
