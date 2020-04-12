// Package base handles the base maps that a system needs to have
// identity.  These maps include the passwd and group map.  On a
// system that uses PAM, these are all you need.  If your system uses
// shadow maps, you will need to load an additional map to handle the
// shadow maps.
package base
