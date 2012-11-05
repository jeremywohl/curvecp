/*
 Status:
  - This Go implementation is a test of protocol and security features.
  - Dan Bernstein's (djb) current implementation, as seen in the NaCl library, is noted as "alpha" and I think these speaks to the
    protocol as well.  This particularly refers to congestion control, but possibly security as well.
  - This Go implementation needs more debugging options, since it currently replaces the many excellent tools transacting with kernel
    interfaces.
  - Congestion control remains unfinished.
  - Many optimizations
 */
