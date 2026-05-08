# Fault Targets

This section highlights the parts of a generic processor that are common targets of fault attacks. Attacks are classified according to the four main components of a processor: inputs, data part, storage, and control part.

| Target Component | Description | Attack Mechanism / Effect |
| :--- | :--- | :--- |
| **Inputs (Input Parameters)** | Interface providing external parameters or reading from non-volatile memory. | Triggering precise faults by manipulating input parameters. This is feasible if the adversary can influence inputs and the implementation lacks validity checks. |
| **Data Processing Part** | Modules responsible for data arithmetic and logic operations. | Disturbing the device during computation to cause erroneous intermediate or final results. Similar effects can be achieved by injecting faults during bus transfers or while data is stored in registers. |
| **Storage Part** | Memory modules (volatile and non-volatile). These are common targets because they occupy significant chip area and have regular structures that are easily distinguishable. | **Volatile Memory:** Exploited to alter intermediate computation results.<br>**Non-volatile Memory:** Tampering can affect system parameters. |
| **Control Part (Instruction Processing)** | Units managing program flow and instruction execution. | Attacking the program flow rather than the data path. This includes forcing the processor to skip instructions or misinterpret them. |
