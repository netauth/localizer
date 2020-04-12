# NetAuth Localizer

The localizer is a component of the NetAuth stack which directly
manages `passwd`, `group`, and `shadow` databases.  The service edits
these files periodically to add and remove users and groups that are
above the threshold of an optional cutoff specified by an
administrator, by default UIDs and GIDs greater than 2000.

## Why not NSS?

NSS is shockingly difficult to work with, and surprisingly buggy
internally.  Its also not available in a meaningful way outside of
glibc, which limits its usefulness.  Furthuremore, NSS uses shared
modules which have to be loaded into a program's address space, or
otherwise loaded by some persistent process on the system.  This makes
it cumbersome ti isolate security domains with potentially every
application on the system needing to load NSS modules.
