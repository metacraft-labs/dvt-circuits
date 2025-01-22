## Install SP1 ##
curl -L https://sp1.succinct.xyz | bash
PATH="$PATH:~/.sp1/bin"
sp1up


## Run test ##

make test

to run single test 

 make test ARGS='--filter text_to_match'

## Build ##

cargo build

## Run ##

1. Prove that some exchanged change is wrong
2. Prove that crypted responce to the changed is not in the valid format
3. Prove some of the participaten generate the wrong share
4. Prove that dvt algorithm is properly executed
