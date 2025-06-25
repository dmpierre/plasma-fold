# PlasmaFold 

PlasmaFold, a payment L2 reaching 14k+ TPS.

PlasmaFold operates under a "verifiable plasma" regime. On one hand, it uses plasma-like data availability requirements, restricting the amount of data posted by an aggregator to minimal amounts. On the other, it requires the plasma aggregator to verifiably build blocks and users to run a (lightweight) client-side prover.

This combination removes from the aggregator most of its cheating avenues while allowing usrs to exit the chain non-interactively at any point in time, without any particular assumptions regarding their liveness.

Our prototype implementation demonstrates a PlasmaFold aggregator running on low-end hardware and an efficient WASM client-side prover running within a chrome browser.

## Tests

PlasmaFo
