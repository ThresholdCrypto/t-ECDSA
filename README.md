## A Robust Threshold ECDSA via Lightweight Multiplicative Triples for Optimal Offline and Online Phases
### Introduction
This is an implementation of the novel threshold ECDSA scheme, corresponding to the paper submitted to USENIX Security 2026. 
This library mainly includes four sub-protocols:
* Public Verifiable Secret Sharing (PVSS) for creating undetermined secret shares with no trusted dealer ("cmd/kGen/PVSS.go").
* A novel BMtP based on threshold linear homomorphic encryption (TLHE) for generating the triples used to compute the additive shares of the multiplicative values ("internal/BMtP/bmtp.go").
* Offline pre-signing protocol for pre-generating the additive shares of the multiplicative values involved in the distributed signature ("cmd/Sign/sign.go").
* Online signing protocol for computing the signature value using the message and the secret shares ("cmd/Sign/sign.go").
### Implementation (linux system, go 1.23.0)
* Install Dependencies: "go mod download".
* Run a Test Example: run this command "go run main.go" in the home directory. This is an example of the 18-out-of-20 threshold for the implementation of this scheme.
