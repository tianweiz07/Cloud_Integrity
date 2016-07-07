# VMI
Using LibVMI to detect malware

syscall-trace and syscall-trace1: when running the process in the OS first, and then list the API call. When restarting the process, pid cannot display correctly. I believe this is a bug from the vmi_dtb_to_pid function. 
