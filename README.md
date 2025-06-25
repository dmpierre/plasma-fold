# PlasmaFold 

<p align="center">
  <img width="180" alt="plasma-fold" src="https://github.com/user-attachments/assets/c19cbc72-e426-4ac7-b421-331bd76146d6" width="30%" height="30%" />
</p>

PlasmaFold: an incrementally verifiable payment L2 combining client-side proving and plasma to reach 14k+ TPS.

PlasmaFold operates under a "verifiable plasma" regime. On one hand, it uses plasma-like data availability requirements, restricting the amount of data posted by an aggregator to minimal amounts. On the other, it requires the plasma aggregator to verifiably build blocks and users to run a (lightweight) client-side prover. This combination removes from the aggregator most of its cheating avenues while allowing usrs to exit the chain non-interactively at any point in time, without any particular assumptions regarding their liveness.

Using [Nova](https://eprint.iacr.org/2021/370.pdfhttps://eprint.iacr.org/2021/370.pdf), our prototype implementation demonstrates a PlasmaFold aggregator working on low-end hardware and an efficient WASM client-side prover running within a chrome browser.

## Benchmarks

**Client**

With SHA Accumulator:

| Transaction Batch size  | `fcircuit`  size | Total circuit size  | Processing time | WASM mem. usage | Parameters size (compressed)|
|---|---|---|---|---|---|
| 1  | 94k | 150k | 4.1s  | 441mb | 97mb |
| 2  | 111k | 167k | 4.7s | 490mb | 114mb |
| 5  | 161k | 218k | 6.2s | 653mb | 164mb |
| 8  | 212k | 268k | 7.8s | 908mb | 232mb |
| 10 | 246k | 302k | 8.8s | 1050mb | 266mb |

With Poseidon accumulator (requires user to provide a side proof to exit - see eprint):

| Transaction Batch size  | `fcircuit`  size | Total circuit size  | Processing time | WASM mem. usage | Parameters size (compressed)|
|---|---|---|---|---|---|
| 1  | 19k (< recursive cost) | 76k | 2.8s  | 291mb | 73mb |
| 2  | 36k (< recursive cost) | 92k | 3.5s  | 343mb | 90mb |
| 5  | 87k | 143k | 5.3s | 579mb | 149mb |
| 8  | 138k | 193k | 7.3s  | 737mb | 200mb |
| 10 |  171k | 227k | 8.1s  | 845mb  | 233mb |

**Aggregator**

## Tests

Tests for PlasmaFold's datastructures and aggregator run natively. Client tests run in wasm within the browser and assume a working installation of [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/).

```
$ cargo test -r -p plasma-fold # datastructures tests
$ cargo test -r -p aggregator # aggregator tests
$ cd client && wasm-pack test -r --chrome --headless # client tests
```
