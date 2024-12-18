Installation

## Install SP1 ##
curl -L https://sp1.succinct.xyz | bash
PATH="$PATH:~/.sp1/bin"
sp1up

## Verify installation ##
cargo prove --version
# Output is cargo-prove sp1 (459fac7 2024-09-14T00:03:44.415694661Z)


## Run test ##

make test