## Install SP1
curl -L https://sp1.succinct.xyz | bash
PATH="$PATH:~/.sp1/bin"
sp1up


## Run test

```
make test
```

to run single test 
```
 make test ARGS='--filter text_to_match'
```

## Build

cargo build

## Produce prove

```
./target/release/dvt_prover_host --input-file input_file.json --type share
```

for more information 

```
./target/release/dvt_prover_host --help
```

## Proves

### Invalid Share

Demonstrates that some participants have sent an incorrect share.

### Successful Final Verification

Confirms that the DVT algorithm has completed successfully.

### Incorrect Final Share Generation

Shows that certain participants provided an invalid final share, though the algorithm can't conclude.

### Malicious Share Exchange Encryption

Reveals that some participants have sent improperly encrypted data that is either incorrect or malicious, violating the algorithm's invariants.


