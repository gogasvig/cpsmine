# cpsmine
Python3 script to estimate flood protection values for PaloAlto firewalls.

This is based on the Python2 version by Glenn Hårseide.

See Glenns' [article](http://netsec.harseide.com/how-to-get-a-baseline-for-flood-protection/)
for details.

This is mostly a rewrite from Python2 to Python3 but I also unrolled
one of the loops so it runs much faster ( O(n) versus O(n^2)).
