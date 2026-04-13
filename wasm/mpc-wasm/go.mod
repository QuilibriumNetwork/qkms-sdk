module github.com/quilibrium/qkms-sdk/wasm/mpc-wasm

go 1.23

require (
	github.com/consensys/gnark-crypto v0.5.3
	source.quilibrium.com/quilibrium/monorepo/nekryptology v0.0.0
)

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/btcsuite/btcd v0.21.0-beta.0.20201114000516-e9c7a5ac6401 // indirect
	github.com/bwesterb/go-ristretto v1.2.3 // indirect
	github.com/cloudflare/circl v1.3.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
)

replace source.quilibrium.com/quilibrium/monorepo/nekryptology => ../../../ceremonyclient/nekryptology
