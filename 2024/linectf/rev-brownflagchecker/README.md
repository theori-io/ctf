# BrownFlagChecker

The challenge provides a sys driver and a PE executable. The sys driver performs protections such as anti-debugging and integrity checks of the text section, and it manipulates the page table to create a new virtual address space. The PE executable retrieves this address space through `DeviceIoControl` and uses it for flag verification.

By analyzing this process, it was possible to calculate the memory values used during flag verification and we could get the flag.

# Flag
LINECTF{72f9fc0fdf5129a4930286e5b9794e10}