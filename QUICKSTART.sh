# Quickstart: how to get a working instance of tlspool.

# First, install git (through your package manager or if you use a
# computer platform which doesn't have one manually, see:
# https://git-scm.com/downloads)
# and nix (see: http://nixos.org/nix/manual/#chap-installation )

# The assumption is that you are using a shell environment.

# Create a working directory (or 'folder') called 'software'

mkdir software && cd software

# (note that you can do this whereever you want on your system, but
# you should name the directory software as this path is hardcoded into
# the nix expression for now (so we can update tlspool with a simple git
# git pull from the main repository)

# Then clone the tlspool repository and the nixpkgs repository:

git clone https://github.com/arpa2/tlspool
git clone https://github.com/arpa2/nixpkgs

# Go into the nixpkgs folder and switch to the tlspool branch:

cd nixpkgs
export NIXPKGS="$PWD" 
git checkout tlspool

# Install tlspool and all the dependencies:

nix-env -f "$NIXPKGS" -iA tlspool

# You can now go into the ../tlspool directory and edit files
# you want to edit. If you want to rebuild tlspool, just reexecute
# nix-env -f $NIXPKGS -iA tlspool

# A simple git pull will update either.

# NB: for SoftHSM you will need to create a config file 

# You can create a file called ~/.config/softhsm2/softhsm2.conf
# with the following content:
# --------------------------------------------------------------
#   directories.tokendir = ~/tokendir/
#   objectstore.backend = file
#   log.level = DEBUG
# --------------------------------------------------------------

# After that you can initiate a token with:

# softhsm2-util --init-token --free --label 'TLS_Pool_dev_data'
