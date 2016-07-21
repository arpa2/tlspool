#! /usr/bin/env sh

# Copyright: the ARPA2 project. See LICENSE-USERSPACE.MD
#
# Quickstart: how to get a working instance of tlspool.

# The assumption is that you are using a shell environment.
# First we check for a few necessary programs. 

PROGRAMS="nix-env git"

for requiredProg in $PROGRAMS
do
  command -v $requiredProg >/dev/null && continue || { printf "$requiredProg is not available. Please install."; exit 1; }
done

# If you start with nix you can install git (if you don't have it) from there 
# with "nix-env -i git".

# See: http://nixos.org/nix/manual/#chap-installation).

# Alternatively you can install git through your package manager.
# If you use a computer platform which doesn't have one, see:
# https://git-scm.com/downloads). 

printf "QUICKSTART.sh from ARPA2 project's TLS Pool here.\n\n"
printf "Usage: QUICKSTART.sh /path/you/want subdirectory_name.\n\n"

# User can indicate where to install everything by providing the 
# desired path and subfolder name as an argument to the script. By default 
# everything is placed in a time-stamped folder located directly under the 
# current folder or directory. 

# First we check to see if there are any arguments, then we clean them up.

if [ -z "$1" ]; then
  BASEDIR=$PWD
else
  if [ -d "$1" ]; then
    # Clean up trailing slashes etc
    x="$1"
    case $x in
      *[!/]*/) BASEDIR=${x%"${x##*[!/]}"};;
    esac
  fi
fi

if [ -z "$2" ]; then
  WORKINGDIR="$(date '+%Y-%m-%d')-tlspool-environment";
else
  y="$2"
  WORKINGDIR=${y##*/};
fi

# Ask the user if the settings are okay, and if she or he agrees with proceeding. 

printf "I'm going to create a subdirectory called $WORKINGDIR in $BASEDIR and install tlspool using nix.\n"
printf "You'll get a local copy of ARPA2's nixpkgs for free.\nAre you okay with that (y/n)? "

old_stty_cfg=$(stty -g)
stty raw -echo ; answer=$(head -c 1) ; stty $old_stty_cfg 
if printf "$answer" | grep -iq "^y" ;then
  printf "\nGreat. I'll get to work in $BASEDIR/$WORKINGDIR. Big stuff, might take a while to download.\n"
else
  printf "\nGood that you told me. \nIf you change your mind, let me know. \n"
  
  printf "Bye.\n"
  exit 1;
fi

# Let's make sure the working directory exists, and go there

if [ ! -d "$BASEDIR/$WORKINGDIR" ]; then
  mkdir "$BASEDIR/$WORKINGDIR"
fi

cd "$BASEDIR/$WORKINGDIR"

# By keeping the tlspool and nixpkgs repositories inside the same folder we can update
# tlspool with a simple "git pull" from the main repository and nix-build command.

if [ ! -d "tlspool" ]; then
  git clone https://github.com/amarsman/tlspool
  cd tlspool
  git checkout tlspool-gui
  cd ..
else
  cd tlspool
  git checkout tlspool-gui
  git pull https://github.com/amarsman/tlspool
  cd ..
fi

if [ ! -d "nixpkgs" ]; then
  git clone https://github.com/amarsman/nixpkgs
  cd nixpkgs
  git checkout tlspool-gui
  cd ..
else
  cd nixpkgs
  git checkout tlspool-gui
  git pull https://github.com/amarsman/nixpkgs
  cd ..
fi

if [ ! -d "steamworks" ]; then
  git clone https://github.com/arpa2/steamworks
else
  cd steamworks 
  git pull https://github.com/arpa2/steamworks
  cd ..
fi

if [ ! -d "tlspool-gui" ]; then
  git clone https://github.com/amarsman/tlspool-gui
else
  cd steamworks 
  git pull https://github.com/amarsman/tlspool-gui
  cd ..
fi

# Go into the nixpkgs folder and switch to the tlspool branch:

cd nixpkgs
export NIXPKGS="$BASEDIR/$WORKINGDIR/nixpkgs"
git checkout tlspool-gui

# Install tlspool and all the dependencies through nix:

nix-env -f "$NIXPKGS" -iA tlspool
nix-env -f "$NIXPKGS" -iA tlspool-gui

cd ..

# NB: for SoftHSM you will need to create a config file
CONFIGFILE="$HOME/.config/softhsm2/softhsm2.conf";

# This will have the following minimal contents
LINE1a="directories.tokendir = ";
LINE1b="/path/to/tokendir/";
LINE2="objectstore.backend = file";
LINE3="log.level = DEBUG";

# Does the user already have a SoftHSM2 config file?

if [ ! -e "$CONFIGFILE" ];
then

  printf "Don't forget to create the config file for SoftHSM2\n"
  printf "You can create a file named $CONFIGFILE"
  printf "with the following suggested content:\n"
  printf  "%s\n--------\n";
  printf "$LINE1a$LINE1b\n$LINE2\n$LINE3\n"
  printf  "%s\n--------\n";
  printf "After that you can initiate a token with:\n\n"
  printf "softhsm2-util --init-token --free --label 'TLS_Pool_dev_data'\n\n"

  printf "Do you want me to create the config file for you, with tokendir pointing to ./$WORKINGDIR/token (y/n)? "
  stty raw -echo ; answer=$(head -c 1) ; stty $old_stty_cfg 

  if echo "$answer" | grep -iq "^y" ; then
    # Make sure config directory and token directory exist
    if [ ! -d "$HOME/.config/softhsm2" ]; then 
      mkdir -p "$HOME/.config/softhsm2"
    fi
    if [ ! -d "$BASEDIR/$WORKINGDIR/token" ]; then 
      mkdir -p "$BASEDIR/$WORKINGDIR/token"
    fi
    # Create the config file and check wether it was created.
    printf "$LINE1a$BASEDIR/$WORKINGDIR/token\n$LINE2\n$LINE3\n" >> "$CONFIGFILE"
    if [ -e "$CONFIGFILE" ]; then 
      printf "\nSoftHSMv2 configuration file $CONFIGFILE created.\n"
    fi
    # Now, given that there was no config, surely there will not be a token. 
    # So should we generate it? Let's ask.
    printf "\nDo you want to generate a token (y/n)?"
    stty raw -echo ; answer=$(head -c 1) ; stty $old_stty_cfg 
    if echo "$answer" | grep -iq "^y" ; then
      printf "\nDon't forget to write down your PIN numbers.\n"
      softhsm2-util --init-token --free --label 'TLS_Pool_dev_data'
    fi
  else
      printf "\nSoftHSM doesn't work without a config file. But you probably already got that.\n"
      exit 1;
  fi
else
  printf "You've already got a config file for SoftHSM2. Great."
fi

printf "\n\nYou can now go into the ../tlspool directory and edit files "
printf "you want to edit. If you want to rebuild tlspool, just reexecute\n\n"
printf "nix-env -f $NIXPKGS -iA tlspool\n\n"

UPDATESCRIPT="$BASEDIR/$WORKINGDIR/update-tlspool.sh"

if [ ! -e $UPDATESCRIPT ]; then
  printf "#! /usr/bin/env sh\n\n# Created by QUICKSTART.sh.\n$SHELL $BASEDIR/$WORKINGDIR/tlspool/QUICKSTART.sh '$BASEDIR' '$WORKINGDIR'\n" > $UPDATESCRIPT
  chmod +x $UPDATESCRIPT;
fi

printf "A simple git pull will update either.\n\nOr just copy $UPDATESCRIPT to wherever you want it to be.\n\n"

printf "You can run 'tlspool -c configfile'. There is an example config file at "
printf "~/.nix-profile/etc/tlspool/tlspool.conf which you can modify for usage." 
