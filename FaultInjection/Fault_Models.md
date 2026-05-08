# Fault Models Summary

The following table summarizes the basic properties of fault injection used to characterize an attack (fault model).

| Property | Classification | Description |
| :--- | :--- | :--- |
| **Controllability over Fault Location** | Precise Control | Attacker can affect a single specific bit of a specific variable. |
| | Loose Control | Attacker can target a specific variable, but not a specific part of it. |
| | No Control | Attacker affects a variable at random. |
| **Controllability over Fault Timing** | Precise Control | Attacker can affect a specific variable at a specific point in time. |
| | Loose Control | Attacker can target a set of operations or clock cycles, but not a specific one. |
| | No Control | Attacker has no control over when the fault occurs. |
| **Number of Affected Bits** | Single bit faults | Only one bit is affected. |
| | Word-size faults | Affects a word (typically 8, 16, 32, or 64 bits, depending on architecture). |
| | Variable-size faults | Affects a variable number of bits. |
| **Effect of a Fault** | Stuck-at fault | Signal or bit fixed at a specific value (0 or 1). |
| | Bit flip fault | Value of the bit is inverted. |
| | Set/reset fault | Forced to a set or reset state. |
| | Random fault | Resulting value is random. |
| **Duration of the Fault** | Transient | Lasts for a limited period; correct value returns (e.g., during bus transfer). |
| | Permanent | Affects variable until explicitly overwritten (e.g., in memory storage). |
| | Destructive | Damages physical layer; bits fixed at specific value; irreversible (e.g., stuck-at logic/memory). |
| | Remanent | Specific to SRAM-based FPGAs; error in configuration memory changes architecture. Placed between permanent and destructive. |
