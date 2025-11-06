build:
	RUSTFLAGS="--cfg zcash_unstable=\"zfuture\"" cargo build --features internal-miner,tx_v6 --release
