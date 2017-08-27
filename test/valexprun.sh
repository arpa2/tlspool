#! /bin/sh
#
# Runner for valexprun tests
#  arg 1: /path/to/valexprun-executable
#  arg 2: /path/to/srcdir
#  arg 3: name of data file in data-valexp-in/
EXE="$1"
SRCDIR="$2"
INFILE="$3"

INDIR="$SRCDIR"/data-valexp-in/
INPUT="$INDIR$INFILE"
OUTPUT="$SRCDIR/data-valexp-out/$INFILE"

test -x "$EXE" || { echo "Missing executable" ; exit 1 ; }
test -f "$INPUT" || { echo "Missing input $INPUT" ; exit 1 ; }
test -f "$OUTPUT" || { echo "Missing output $OUTPUT" ; exit 1 ; }


"$EXE" `cat "$INPUT"` > out-"$INFILE"
diff -u "$OUTPUT" out-"$INFILE"
