#include "vmi.h"

vmi_event_t execve_enter_event;
vmi_event_t execve_step_event;

addr_t virt_do_execve;
addr_t phys_do_execve;

#ifndef MEM_EVENT
uint32_t do_execve_orig_data;
#endif


/* file struct offset */
unsigned long fs_offset;
unsigned long dentry_offset;
unsigned long parent_offset;
unsigned long iname_offset;

/*
  To get this, run the following commands:
    kpartx -l vm.img
    kpartx -a vm.img
    mkdir /mnt/vm3

*/
const char *mount_src = "/dev/mapper/uvm3-root";
const char *mount_dest = "/mnt/vm3";

unsigned char **sig_list;
int num_sig;

int cal_hash(char *exec_path, unsigned char *hash_val) {
    char mount_path[256] = "";
    strcpy(mount_path, mount_dest);
    strcat(mount_path, exec_path);

    mount(mount_src, mount_dest, "ext4", MS_RDONLY | MS_SYNCHRONOUS, NULL);

    int n;
    MD5_CTX c;
    char buf[512];
    ssize_t bytes;
    unsigned char out[MD5_DIGEST_LENGTH];

    int file = open(mount_path, O_RDONLY);

    MD5_Init(&c);
    bytes=read(file, buf, 512);
    while(bytes > 0) {
        MD5_Update(&c, buf, bytes);
        bytes=read(file, buf, 512);
    }

    MD5_Final(out, &c);

    strcpy(hash_val, out);

    close(file);
    umount(mount_dest);

    return 0;
}


int find_absolute_path(vmi_instance_t vmi, vmi_pid_t pid, char *executable, char *exec_path) {
    char **dirs = NULL;
    char *p = strtok(executable, "/");
    int n = 0, i;
    while (p) {
        dirs = realloc(dirs, sizeof(char*) * ++n);
        dirs[n-1] = p;
        p = strtok(NULL, "/");
    }

    char **abs_path = NULL;
    int abs_n = 0;
    int flag = 0;
    for (i=n-1; i>=0; i--) {
        if(!strcmp(dirs[i], "."))
            continue;
        if(!strcmp(dirs[i], "..")) {
            flag = 1;
            continue;
        }
        if (flag == 0) {
            abs_path = realloc(abs_path, sizeof(char*) * ++abs_n);
            abs_path[abs_n-1] = (char *)malloc(256);
            strcpy(abs_path[abs_n-1], dirs[i]);
        }
    }

    /**
     * The parameter is a relative path. Convert it to absolute path 
     */
    if ((!strcmp(dirs[0], "."))||(!strcmp(dirs[0], ".."))) {
        addr_t list_head = 0, next_list_entry = 0, current_process = 0;
        vmi_pid_t pid1 = 0;

        addr_t addr_init_task;
        vmi_translate_ksym2v(vmi, "init_task", &addr_init_task);

        list_head = addr_init_task + tasks_offset;
        next_list_entry = list_head;

        do {
            current_process = next_list_entry - tasks_offset;
            vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid1);
            if (pid1 == pid) {
                char *procname = NULL, *dirname = NULL;
                procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
                if (!procname) {
                    printf("Failed to find procname\n");
                    return -1;;
                }

                addr_t fs_addr, dentry_addr;
                vmi_read_addr_va(vmi, current_process+fs_offset, 0, &fs_addr);
                vmi_read_addr_va(vmi, fs_addr+dentry_offset, 0, &dentry_addr);
                dirname = vmi_read_str_va(vmi, dentry_addr+iname_offset, 0);
                while (strcmp("/", dirname)) {
                    if (flag == 1) {
                        flag = 0;
                    } else {
                        abs_path = realloc(abs_path, sizeof(char*) * ++abs_n);
                        abs_path[abs_n-1] = (char *)malloc(100);
                        strcpy(abs_path[abs_n-1], dirname);
                    }
                    vmi_read_addr_va(vmi, dentry_addr+parent_offset, 0, &dentry_addr);
                    dirname = vmi_read_str_va(vmi, dentry_addr+iname_offset, 0);
                }
                break;
            }
            status_t status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
            if (status == VMI_FAILURE) {
                printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
                return -1;
            }
        } while(next_list_entry != list_head);
    }

    for (i=abs_n-1; i>=0; i--) {
        strcat(exec_path, "/");
        strcat(exec_path, abs_path[i]);
    }

    return 0;
}



event_response_t execve_step_cb(vmi_instance_t vmi, vmi_event_t *event) {
    /**
     * enable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    vmi_register_event(vmi, &execve_enter_event);
#else
    execve_enter_event.interrupt_event.reinject = 1;
    if (set_breakpoint(vmi, virt_do_execve, 0) < 0) {
        printf("Could not set break points\n");
        exit(1);
    }
#endif

    /** 
     * disable the single event
     */
    vmi_clear_event(vmi, &execve_step_event, NULL);
    return 0;
}


event_response_t execve_enter_cb(vmi_instance_t vmi, vmi_event_t *event){
#ifdef MEM_EVENT
    if (event->mem_event.gla == virt_do_execve) {
#else
    if (event->interrupt_event.gla == virt_do_execve) {
#endif
        reg_t rdi, cr3, rsp;
        vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        vmi_get_vcpureg(vmi, &rsp, RSP, event->vcpu_id);

        vmi_pid_t pid = -1;
        vmi_dtb_to_pid(vmi, cr3, &pid);

        char *executable = NULL;
        char exec_path[256] = "";

        /**
         * find the executable and its absolute path
         */
        executable = vmi_read_str_va(vmi, rdi, pid);
        find_absolute_path(vmi, pid, executable, exec_path);

        printf("Process[%d] invokes sys_execve: %s\n", pid, exec_path);


        /**
         * calculate the hash value of the executable
         */
        unsigned char hash_val[MD5_DIGEST_LENGTH];
        cal_hash(exec_path, hash_val);
        int n;
        for(n=0; n<MD5_DIGEST_LENGTH; n++)
            printf("%d ", hash_val[n]);
        printf("\n");


        int i;
        for (i=0; i<num_sig; i++) {
            if (!strncmp(hash_val, sig_list[i], MD5_DIGEST_LENGTH)) {

                /** 
                 * We can change the API's parameter into invalid, via modifying RDI registers. 
                 */
/*
                if (!strcmp(filename, "./hello")) {
                    uint32_t var = 0x0;
                    vmi_write_32_va(vmi, rdi, pid, &var);
                }
*/
                /**
                 * or change the code path by modifying the RIP register, and return values in RAX 
                 */

                /**
                 * Pop RIP out of stack
                 */
                vmi_set_vcpureg(vmi, rsp+8, RSP, event->vcpu_id);
                /** 
                 * Invalid the return value. If the return value is a pointer, can change to 0x0
                 */
                vmi_set_vcpureg(vmi, -1, RAX, event->vcpu_id);
                /**
                 * Change the RIP to the old one
                 */
                uint64_t rip;
                vmi_read_64_va(vmi, rsp, pid, &rip);
                vmi_set_vcpureg(vmi, rip, RIP, event->vcpu_id);

                break;
            }
        }
    }

    /**
     * disable the syscall entry interrupt
     */
#ifdef MEM_EVENT
    vmi_clear_event(vmi, event, NULL);
#else
    event->interrupt_event.reinject = 0;
    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_do_execve, 0, &do_execve_orig_data)) {
        printf("failed to write memory.\n");
        exit(1);
    }
#endif

    /**
     * set the single event to execute one instruction
     */
    vmi_register_event(vmi, &execve_step_event);
    return 0;
}

int introspect_process_block (char *name) {

    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    vmi_instance_t vmi = NULL;
    vmi_init_data_t *init_data = NULL;
    uint8_t init = VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *input = NULL, *config = NULL;
    vmi_init_error_t *error = NULL;

    vmi_mode_t mode;
    if (VMI_FAILURE == vmi_get_access_mode(NULL, name, VMI_INIT_DOMAINNAME| VMI_INIT_EVENTS, init_data, &mode)) {
        printf("Failed to find a supported hypervisor with LibVMI\n");
        return 1;
    }

    /* initialize the libvmi library */
    if (VMI_FAILURE == vmi_init(&vmi, mode, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    if ( VMI_PM_UNKNOWN == vmi_init_paging(vmi, 0) ) {
        printf("Failed to init determine paging.\n");
        vmi_destroy(vmi);
        return 1;
    }

    if ( VMI_OS_UNKNOWN == vmi_init_os(vmi, VMI_CONFIG_GLOBAL_FILE_ENTRY, config, error) ) {
        printf("Failed to init os.\n");
        vmi_destroy(vmi);
        return 1;
    }
    /**
     * get the list of process signatures that to block their launch, from the file blacklist.txt.
     */
    num_sig = 0;
    char _line[256];
    char _name[256];
    char *data;

    int offset;
    unsigned char sig[MD5_DIGEST_LENGTH];

    int i, j;
    FILE *_file = fopen("blacklist.txt", "r");
    while(fgets(_line, sizeof(_line), _file) != NULL){
        data = _line;
        sscanf(data, "%s%n", _name, &offset);
        data += offset;
        for (i=0; i<MD5_DIGEST_LENGTH; i++) {
            sscanf(data, " %hhu%n", &(sig[i]), &offset);
            data += offset;
        }
        sig_list = realloc(sig_list, sizeof(char*) * ++num_sig);
        sig_list[num_sig-1] = (unsigned char*) malloc(MD5_DIGEST_LENGTH);
        strncpy(sig_list[num_sig-1], sig, MD5_DIGEST_LENGTH);
    }
    fclose(_file);

    /**
     * get the offsets from the libvmi config file
     */
    vmi_get_offset(vmi, "linux_tasks", &tasks_offset);
    vmi_get_offset(vmi, "linux_name", &name_offset);
    vmi_get_offset(vmi, "linux_pid", &pid_offset);
   
    /**
     * file struct offsets can be obtained by running findpwd 
     */
    fs_offset = 0x530;
    dentry_offset = 0x28;
    parent_offset = 0x28;
    iname_offset = 0xa0;

    /**
     * get the address of function do_execve
     */
    vmi_translate_ksym2v(vmi, "do_execve", &virt_do_execve);
    vmi_translate_kv2p(vmi, virt_do_execve, &phys_do_execve);

    memset(&execve_enter_event, 0, sizeof(vmi_event_t));

#ifdef MEM_EVENT
    /**
     * iniialize the memory event for EPT violation.
     */
    uint64_t gfn = phys_do_execve >> 12;
    SETUP_MEM_EVENT(&execve_enter_event, gfn, VMI_MEMACCESS_X, &execve_enter_cb, false);
#else
    /**
     * iniialize the interrupt event for INT3.
     */
    execve_enter_event.type = VMI_EVENT_INTERRUPT;
    execve_enter_event.interrupt_event.intr = INT3;
    execve_enter_event.callback = execve_enter_cb;
#endif

    /**
     * iniialize the single step event.
     */
    memset(&execve_step_event, 0, sizeof(vmi_event_t));
    execve_step_event.type = VMI_EVENT_SINGLESTEP;
    execve_step_event.callback = execve_step_cb;
    execve_step_event.ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(execve_step_event.ss_event, 0);

    /**
     * register the event.
     */
    if(vmi_register_event(vmi, &execve_enter_event) == VMI_FAILURE) {
        printf("Could not install enter syscall handler.\n");
        goto exit;
    }

#ifndef MEM_EVENT
    /**
     * store the original data for syscall entry function
     */
    if (VMI_FAILURE == vmi_read_32_va(vmi, virt_do_execve, 0, &do_execve_orig_data)) {
        printf("failed to read the original data.\n");
        vmi_destroy(vmi);
        return -1;
    }

    /**
     * insert breakpoint into the syscall entry function
     */
    if (set_breakpoint(vmi, virt_do_execve, 0) < 0) {
        printf("Could not set break points\n");
        goto exit;
    }
#endif

    while(!interrupted){
        if (vmi_events_listen(vmi, 1000) != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }

exit:

#ifndef MEM_EVENT
    /**
     * write back the original data
     */
    if (VMI_FAILURE == vmi_write_32_va(vmi, virt_do_execve, 0, &do_execve_orig_data)) {
        printf("failed to write back the original data.\n");
    }
#endif

    vmi_destroy(vmi);
    return 0;
}
