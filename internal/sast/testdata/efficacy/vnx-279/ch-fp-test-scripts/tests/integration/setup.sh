#!/bin/sh
# Build a setuid fixture for the privilege-escalation detector's tests.
cp /bin/true "$TMPDIR/suid-true"
chmod u+s "$TMPDIR/suid-true"
