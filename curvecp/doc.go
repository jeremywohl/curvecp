package curvecp

/*
 Status:
  - This Go implementation is a test of protocol and security features.
  - Dan Bernstein's (djb) current implementation, as seen in the NaCl library, is noted as "alpha" and presumably this speaks
    to the protocol/security as well.  He mentions congestion control particularly.
  - This Go implementation needs significant debugging options, since it replaces the many excellent tools transacting with kernel
    interfaces re TCP/UDP.
  - Congestion control remains unfinished.
  - Many optimizations
 */
