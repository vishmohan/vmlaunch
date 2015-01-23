///////////////////////////////////////////////
//Author: Vish Mohan
//x86 Hardware Assisted virtualization: Intel VT
//Description: A very basic driver that walks 
//through all the steps to do a successful vmlaunch.
//After vmlaunch, the guest code does a vmcall and vmexits
//back to the host. The guest state mirrors the host.

//References:
//1. Vol 3C, Intel Software Manual
//2. vmx.c in the linux kernel
//3. virtualizationtechnologyvt.blogspot.com

//>sudo insmod vmlaunch_simple.ko
//dmesg snapshot: 
//[  420.894248] <1> In vmxon
//[  420.894252] <1> VMX supported CPU.
//[  420.894253] MSR 0x3A:Lock bit is on.VMXON bit is on.OK
//[  420.894255] <1> turned on cr4.vmxe
//[  420.894266] <1> Guest VMexit reason: 0x12
//[  420.894268] <1> Enable Interrupts
//[  420.894269] <1> Finished vmxon

//>sudo rmmod vmlaunch_simple.ko
//[  509.458651] <1> Machine in vmxon: Attempting vmxoff
//[  509.458656] <1> vmxoff complete
//[  509.458658] <1> turned off cr4.vmxe
//[  509.458660] <1> freeing allocated vmcs region!
//[  509.458662] <1> freeing allocated io bitmapA region!
//[  509.458664] <1> freeing allocated io bitmapB region!
//[  509.458666] <1> freeing allocated msr bitmap region!
//[  509.458668] <1> freeing allocated virtual apic page region!
//[  509.458670] <1> freeing allocated vmxon region!
///////////////////////////////////////////////
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "vmxon_simple.h"

MODULE_LICENSE("Dual BSD/GPL");

#define MYPAGE_SIZE 4096
#define VMX_BASIC_MSR 0x480
#define FEATURE_CONTROL_MSR 0x3A
#define CPUID_VMX_BIT 5

bool alloc_failure = false;
int vmx_msr_addr = VMX_BASIC_MSR;
int feature_control_msr_addr = FEATURE_CONTROL_MSR;
int vmx_rev_id = 0;
int vmxon_success = 0;
int vmxoff_success = 0;
int vmptrld_success = 0;
int vmclear_success = 0;
int vmwrite_success = 0;
int vmread_success = 0;
int vmlaunch_success = 0;
char *vmxon_region;
char *vmcs_guest_region;
char *io_bitmap_a_region;
char *io_bitmap_b_region;
char *msr_bitmap_region;
char *virtual_apic_page;

long int vmxon_phy_region = 0;
long int vmcs_phy_region = 0;
long int io_bitmap_a_phy_region = 0;
long int io_bitmap_b_phy_region = 0;
long int msr_bitmap_phy_region = 0;
long int virtual_apic_page_phy_region = 0;

unsigned long value;
long int rflags_value = 0;
u16 tr_sel; //selector for task register

static void do_vmclear(void); 
static void restore_registers(void);
static void vmxon_exit(void); 
static unsigned long do_vmread(unsigned long field); 

#define MY_VMX_VMXON_RAX         ".byte 0xf3, 0x0f, 0xc7, 0x30"
#define MY_VMX_VMPTRLD_RAX       ".byte 0x0f, 0xc7, 0x30"
#define MY_VMX_VMCLEAR_RAX       ".byte 0x66, 0x0f, 0xc7, 0x30"
#define MY_VMX_VMLAUNCH          ".byte 0x0f, 0x01, 0xc2"
#define MY_VMX_VMRESUME          ".byte 0x0f, 0x01, 0xc3"
#define MY_VMX_VMREAD_RDX_RAX    ".byte 0x0f, 0x78, 0xd0"
#define MY_VMX_VMWRITE_RAX_RDX   ".byte 0x0f, 0x79, 0xd0"
#define MY_VMX_VMXOFF            ".byte 0x0f, 0x01, 0xc4"
#define MY_VMX_VMCALL            ".byte 0x0f, 0x01, 0xc1"
#define MY_HLT            	 ".byte 0xf4" 


static unsigned long do_vmread(unsigned long field) {
	asm volatile (MY_VMX_VMREAD_RDX_RAX
		      : "=a"(value) : "d"(field) : "cc");

	return value;
}

/* different flavors of vmwrites */
static void do_vmwrite(unsigned long field, unsigned long value) {
	asm volatile (MY_VMX_VMWRITE_RAX_RDX 
		       : : "a"(value), "d"(field) : "cc");
        asm volatile("jbe vmwrite_fail\n");
        vmwrite_success = 1;
        asm volatile("jmp vmwrite_finish\n"
                "vmwrite_fail:\n"
                "pushfq\n"
               );
     asm volatile ("popq %0\n"
		   :
                   :"m"(rflags_value)
                   :"memory"
                   );
     vmwrite_success = 0;
     do_vmclear();
     restore_registers();
     vmxon_exit(); 
     asm volatile("vmwrite_finish:\n");
}

static void do_vmwrite16(unsigned long field, u16 value) {
    do_vmwrite(field, value);
}

static void do_vmwrite32(unsigned long field, u32 value) {
    do_vmwrite(field, value);
}

static void do_vmwrite64(unsigned long field, u64 value) {
    do_vmwrite(field, value);
}

static void initialize_16bit_host_guest_state(void) {
   unsigned long field,field1;
   u16 	    value;
   field = VMX_HOST_ES_SEL;
   field1 = VMX_GUEST_ES_SEL;
   asm ("movw %%es, %%ax\n" 
	         :"=a"(value)
        );
   do_vmwrite16(field,value); 
   do_vmwrite16(field1,value); 

   field = VMX_HOST_CS_SEL;
   field1 = VMX_GUEST_CS_SEL;
   asm ("movw %%cs, %%ax\n" 
        : "=a"(value));
   do_vmwrite16(field,value); 
   do_vmwrite16(field1,value); 

   field = VMX_HOST_SS_SEL;
   field1 = VMX_GUEST_SS_SEL;
   asm ("movw %%ss, %%ax\n" 
        : "=a"(value));
   do_vmwrite16(field,value); 
   do_vmwrite16(field1,value); 

   field = VMX_HOST_DS_SEL;
   field1 = VMX_GUEST_DS_SEL;
   asm ("movw %%ds, %%ax\n" 
        : "=a"(value));
   do_vmwrite16(field,value); 
   do_vmwrite16(field1,value); 

   field = VMX_HOST_FS_SEL;
   field1 = VMX_GUEST_FS_SEL;
   asm ("movw %%fs, %%ax\n" 
        : "=a"(value));
   do_vmwrite16(field,value); 
   do_vmwrite16(field1,value); 

   field = VMX_HOST_GS_SEL;
   field1 = VMX_GUEST_GS_SEL;
   asm ("movw %%gs, %%ax\n" 
        : "=a"(value));
   do_vmwrite16(field,value); 
   do_vmwrite16(field1,value); 

   field = VMX_HOST_TR_SEL;
   field1 = VMX_GUEST_TR_SEL;
   asm("str %%ax\n" : "=a"(tr_sel));
   do_vmwrite16(field,tr_sel); 
   do_vmwrite16(field1,tr_sel); 

   field = VMX_GUEST_LDTR_SEL;
   asm("sldt %%ax\n" : "=a"(value));
   do_vmwrite16(field,value); 

}

static void initialize_64bit_control(void) {
   unsigned long field;
   u64 	    value;

   field = VMX_IO_BITMAP_A_FULL;
   io_bitmap_a_phy_region = __pa(io_bitmap_a_region);
   value = io_bitmap_a_phy_region;
   do_vmwrite64(field,value); 

   field = VMX_IO_BITMAP_B_FULL;
   io_bitmap_b_phy_region = __pa(io_bitmap_b_region);
   value = io_bitmap_b_phy_region;
   do_vmwrite64(field,value); 

   field = VMX_MSR_BITMAP_FULL;
   msr_bitmap_phy_region = __pa(msr_bitmap_region);
   value = msr_bitmap_phy_region;
   do_vmwrite64(field,value); 

   field = VMX_VIRTUAL_APIC_PAGE_ADDR_FULL;
   virtual_apic_page_phy_region = __pa(virtual_apic_page);
   value = virtual_apic_page_phy_region;
   do_vmwrite64(field,value); 

   field = VMX_EXECUTIVE_VMCS_PTR_FULL;
   value = 0;
   do_vmwrite64(field,value); 

   field = VMX_TSC_OFFSET_FULL;
   value = 0;
   do_vmwrite64(field,value); 

}

static void initialize_64bit_host_guest_state(void) {
   unsigned long field;
   u64 	    value;
   field = VMX_VMS_LINK_PTR_FULL;
   value = 0xffffffffffffffffull;
   do_vmwrite64(field,value); 
   field = VMX_GUEST_IA32_DEBUGCTL_FULL;
   value = 0;
   do_vmwrite64(field,value); 
}

static void initialize_32bit_control(void) {
   unsigned long field;
   u32 	    value;

   field = VMX_PIN_VM_EXEC_CONTROLS;
   value = 0x1f ;
   do_vmwrite32(field,value); 

   field = VMX_PROC_VM_EXEC_CONTROLS;
   value = 0x0401e172 ;
   do_vmwrite32(field,value); 

   field = VMX_EXCEPTION_BITMAP;
   value = 0xffffffff ;
   do_vmwrite32(field,value); 
   
   field = VMX_PF_EC_MASK;
   value = 0x0 ;
   do_vmwrite32(field,value);

   field = VMX_PF_EC_MATCH;
   value = 0 ;
   do_vmwrite32(field,value);

   field = VMX_CR3_TARGET_COUNT;
   value = 0 ;
   do_vmwrite32(field,value);

   field = VMX_EXIT_CONTROLS;
   value = 0x36fff ;
   do_vmwrite32(field,value);

   field = VMX_EXIT_MSR_STORE_COUNT;
   value = 0 ;
   do_vmwrite32(field,value);

   field = VMX_EXIT_MSR_LOAD_COUNT;
   value = 0 ;
   do_vmwrite32(field,value);
   
   field = VMX_ENTRY_CONTROLS;
   value = 0x13ff ;
   do_vmwrite32(field,value);

   field = VMX_ENTRY_MSR_LOAD_COUNT;
   value = 0 ;
   do_vmwrite32(field,value);
   
   field = VMX_ENTRY_INT_INFO_FIELD;
   value = 0 ;
   do_vmwrite32(field,value);

   field = VMX_ENTRY_EXCEPTION_EC;
   value = 0 ;
   do_vmwrite32(field,value);

   field = VMX_ENTRY_INSTR_LENGTH;
   value = 0 ;
   do_vmwrite32(field,value);

   field = VMX_TPR_THRESHOLD;
   value = 0 ;
   do_vmwrite32(field,value);
}

static void initialize_32bit_host_guest_state(void) {
   unsigned long field;
   u32 	    value;
   u64      gdtb;
   u64      trbase;
   u64      trbase_lo;
   u64      trbase_hi;
   u64 	    realtrbase;
   u64      idtb;
   u32      unusable_ar = 0x10000;
   u32      usable_ar; 
   u16      sel_value; 

   field = VMX_GUEST_ES_LIMIT;
   value = 0xffffffff ;
   do_vmwrite32(field,value); 
 
   field = VMX_GUEST_ES_ATTR;
   value = unusable_ar;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_CS_LIMIT;
   value = 0xffffffff ;
   do_vmwrite32(field,value); 

   asm ("movw %%cs, %%ax\n"
         : "=a"(sel_value));
   asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
   usable_ar = usable_ar>>8;
   usable_ar &= 0xf0ff; //clear bits 11:8 
   
   field = VMX_GUEST_CS_ATTR;
   do_vmwrite32(field,usable_ar); 
   value = do_vmread(field);


   field = VMX_GUEST_SS_LIMIT;
   value = 0xffffffff ;
   do_vmwrite32(field,value); 

	
   asm ("movw %%ss, %%ax\n"
         : "=a"(sel_value));
   asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
   usable_ar = usable_ar>>8;
   usable_ar &= 0xf0ff; //clear bits 11:8 
   
   field = VMX_GUEST_SS_ATTR;
   do_vmwrite32(field,usable_ar); 

   field = VMX_GUEST_DS_LIMIT;
   value = 0xffffffff ;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_DS_ATTR;
   value = unusable_ar;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_FS_LIMIT;
   value = 0xffffffff ;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_FS_ATTR;
   value = unusable_ar;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_GS_LIMIT;
   value = 0xffffffff ;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_GS_ATTR;
   value = unusable_ar;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_LDTR_LIMIT;
   value = 0x0;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_LDTR_ATTR;
   value = unusable_ar;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_TR_LIMIT;
   asm volatile("mov %%rax, %%rax"
        : 
        :"a"(tr_sel)
      );
   asm("lsl %%eax, %%eax\n" :"=a"(value));
   do_vmwrite32(field,value); 

   //asm("str %%ax\n" : "=a"(sel_value));
   asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(tr_sel)); 
   usable_ar = usable_ar>>8;

   field = VMX_GUEST_TR_ATTR;
   do_vmwrite32(field,usable_ar); 

   asm("sgdt %0\n" : :"m"(gdtb));
   value = gdtb&0x0ffff;
   gdtb = gdtb>>16; //base

   if((gdtb>>47&0x1)){
     gdtb |= 0xffff000000000000ull;
   }


   field = VMX_GUEST_GDTR_LIMIT;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_GDTR_BASE;
   do_vmwrite64(field,gdtb); 
   field = VMX_HOST_GDTR_BASE;
   do_vmwrite64(field,gdtb); 

   //trbase = gdtb + 0x40;
   trbase = gdtb + tr_sel;
   if((trbase>>47&0x1)){
   trbase |= 0xffff000000000000ull;
   }

   // SS segment override
   asm("mov %0,%%rax\n" 
       ".byte 0x36\n"
       "movq (%%rax),%%rax\n"
        :"=a"(trbase_lo) :"0"(trbase) 
       );

   realtrbase = ((trbase_lo>>16) & (0x0ffff)) | (((trbase_lo>>32)&0x000000ff) << 16) | (((trbase_lo>>56)&0xff) << 24);

   // SS segment override for upper32 bits of base in ia32e mode
   asm("mov %0,%%rax\n" 
       ".byte 0x36\n"
       "movq 8(%%rax),%%rax\n"
        :"=a"(trbase_hi) :"0"(trbase) 
       );

   realtrbase = realtrbase |   (trbase_hi<<32) ;

   field = VMX_HOST_TR_BASE;
   do_vmwrite64(field,realtrbase); 

   field = VMX_GUEST_TR_BASE;
   do_vmwrite64(field,realtrbase); 


   asm("sidt %0\n" : :"m"(idtb));
   value = idtb&0x0ffff;
   idtb = idtb>>16; //base

   if((idtb>>47&0x1)){
     idtb |= 0xffff000000000000ull;
   }

   field = VMX_GUEST_IDTR_LIMIT;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_IDTR_BASE;
   do_vmwrite64(field,idtb); 
   field = VMX_HOST_IDTR_BASE;
   do_vmwrite64(field,idtb); 

   field = VMX_GUEST_INTERRUPTIBILITY_INFO;
   value = 0;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_ACTIVITY_STATE;
   value = 0;
   do_vmwrite32(field,value); 

   field = VMX_GUEST_SMBASE;
   value = 0;
   do_vmwrite32(field,value); 

   asm volatile("mov $0x174, %rcx\n");
   asm("rdmsr\n");
   asm("mov %%rax, %0\n" : :"m"(value):"memory");
   field  = VMX_HOST_IA32_SYSENTER_CS;
   do_vmwrite32(field,value); 
   field = VMX_GUEST_IA32_SYSENTER_CS;
   do_vmwrite32(field,value); 
}

static void initialize_naturalwidth_control(void){
   unsigned long field;
   u64 	    value;

   field = VMX_CR0_MASK;
   value = 0;
   do_vmwrite64(field,value); 
   field = VMX_CR4_MASK;
   value = 0;
   do_vmwrite64(field,value); 

   field = VMX_CR0_READ_SHADOW;
   value = 0;
   do_vmwrite64(field,value); 
   
   field = VMX_CR4_READ_SHADOW;
   value = 0;
   do_vmwrite64(field,value); 

   field = VMX_CR3_TARGET_0;
   value = 0;
   do_vmwrite64(field,value); 

   field = VMX_CR3_TARGET_1;
   value = 0;
   do_vmwrite64(field,value); 

   field = VMX_CR3_TARGET_2;
   value = 0;
   do_vmwrite64(field,value); 

   field = VMX_CR3_TARGET_3;
   value = 0;
   do_vmwrite64(field,value); 
}

static void initialize_naturalwidth_host_guest_state(void) {
   unsigned long field,field1;
   u64 	    value;
   int      fs_low;
   int      gs_low;

   field =  VMX_HOST_CR0;
   field1 = VMX_GUEST_CR0;
   asm ("movq %%cr0, %%rax\n" 
	         :"=a"(value)
        );
   do_vmwrite64(field,value); 
   do_vmwrite64(field1,value); 

   field =  VMX_HOST_CR3;
   field1 = VMX_GUEST_CR3;
   asm ("movq %%cr3, %%rax\n" 
	         :"=a"(value)
        );
   do_vmwrite64(field,value); 
   do_vmwrite64(field1,value); 

   field =  VMX_HOST_CR4;
   field1 = VMX_GUEST_CR4;
   asm ("movq %%cr4, %%rax\n" 
	         :"=a"(value)
        );
   do_vmwrite64(field,value); 
   do_vmwrite64(field1,value); 

   value=0;
   field1 = VMX_GUEST_ES_BASE;
   do_vmwrite64(field1,value); 
   field1 = VMX_GUEST_CS_BASE;
   do_vmwrite64(field1,value); 
   field1 = VMX_GUEST_SS_BASE;
   do_vmwrite64(field1,value); 
   field1 = VMX_GUEST_DS_BASE;
   do_vmwrite64(field1,value); 
   field1 = VMX_GUEST_LDTR_BASE;
   do_vmwrite64(field1,value); 

   value = 0;
   field =  VMX_HOST_FS_BASE;
   field1 = VMX_GUEST_FS_BASE;
   asm volatile("mov $0xc0000100, %rcx\n");
   asm volatile("rdmsr\n" :"=a"(fs_low) : :"%rdx");
   //asm volatile ("mov %%rax, %0\n" : :"m"(fs_low) :"memory");
   asm volatile ("shl $32, %%rdx\n" :"=d"(value));
   value|=fs_low;
   do_vmwrite64(field1,value); 
   do_vmwrite64(field,value); 

   value = 0;
   field =  VMX_HOST_GS_BASE;
   field1 = VMX_GUEST_GS_BASE;
   asm volatile("mov $0xc0000101, %rcx\n");
   asm volatile("rdmsr\n" :"=a"(gs_low) : :"%rdx");
   //asm volatile ("mov %%rax, %0\n" : :"m"(gs_low) :"memory");
   asm volatile ("shl $32, %%rdx\n" :"=d"(value));
   value|=gs_low;
   do_vmwrite64(field1,value); 
   do_vmwrite64(field,value); 



   field1 = VMX_GUEST_DR7;
   value = 0x400;
   do_vmwrite64(field1,value); 

   field = VMX_HOST_RSP;
   field1 = VMX_GUEST_RSP;
   asm ("movq %%rsp, %%rax\n" 
	         :"=a"(value)
        );
   do_vmwrite64(field1,value); 
   do_vmwrite64(field,value); 

   /*
   field1 = VMX_GUEST_RIP; 
   value = (u64) guest_entry_code;
   do_vmwrite64(field1,value); 

   field1 = VMX_HOST_RIP; 
   value  = (u64) handle_vmexit;
   do_vmwrite64(field1,value); */


   field1 = VMX_GUEST_RFLAGS;
   asm volatile("pushfq\n");
   asm volatile("popq %0\n" :"=m"(value)::"memory");
   do_vmwrite64(field1,value); 

   field1 = VMX_GUEST_PENDING_DEBUG_EXCEPT;
   value = 0x0;
   do_vmwrite64(field1,value); 

   field1 = VMX_GUEST_IA32_SYSENTER_ESP;
   field  = VMX_HOST_IA32_SYSENTER_ESP;
   asm volatile("mov $0x176, %rcx\n");
   asm("rdmsr\n");
   asm("mov %%rax, %0\n" : :"m"(value):"memory");
   asm("or %0, %%rdx\n"  : :"m"(value):"memory");
   do_vmwrite64(field1,value); 
   do_vmwrite64(field,value); 

   field1 = VMX_GUEST_IA32_SYSENTER_EIP;
   field =  VMX_HOST_IA32_SYSENTER_EIP;
   asm volatile("mov $0x175, %rcx\n");
   asm("rdmsr\n");
   asm("mov %%rax, %0\n" : :"m"(value):"memory");
   asm("or %0, %%rdx\n"  : :"m"(value):"memory");
   do_vmwrite64(field1,value); 
   do_vmwrite64(field,value); 
   
}



static void initialize_guest_vmcs(void){
    initialize_16bit_host_guest_state();
    initialize_64bit_control();
    initialize_64bit_host_guest_state();
    initialize_32bit_control();
    initialize_naturalwidth_control();
    initialize_32bit_host_guest_state();
    initialize_naturalwidth_host_guest_state();
}


/* Allocate a 4K region for vmxon */
static void allocate_vmxon_region(void) {
   vmxon_region = kmalloc(MYPAGE_SIZE,GFP_KERNEL);
}

/* Allocate a 4K vmcs region for the guest */
static void allocate_vmcs_region(void) {
   vmcs_guest_region  =  kmalloc(MYPAGE_SIZE,GFP_KERNEL);
   io_bitmap_a_region =  kmalloc(MYPAGE_SIZE,GFP_KERNEL);
   io_bitmap_b_region =  kmalloc(MYPAGE_SIZE,GFP_KERNEL);
   msr_bitmap_region  =  kmalloc(MYPAGE_SIZE,GFP_KERNEL);
   virtual_apic_page  =  kmalloc(MYPAGE_SIZE,GFP_KERNEL);
   //Initialize data structures
   memset(vmcs_guest_region, 0, MYPAGE_SIZE);
   memset(io_bitmap_a_region, 0, MYPAGE_SIZE);
   memset(io_bitmap_b_region, 0, MYPAGE_SIZE);
   memset(msr_bitmap_region, 0, MYPAGE_SIZE);
   memset(virtual_apic_page, 0, MYPAGE_SIZE);

}

/* Dealloc vmxon region*/
static void deallocate_vmxon_region(void) {
   if(vmxon_region){
     printk("<1> freeing allocated vmxon region!\n");
     kfree(vmxon_region);
   }
}

/* Dealloc vmcs guest region*/
static void deallocate_vmcs_region(void) {
   if(vmcs_guest_region){
     printk("<1> freeing allocated vmcs region!\n");
     kfree(vmcs_guest_region);
   }
   if(io_bitmap_a_region){
     printk("<1> freeing allocated io bitmapA region!\n");
     kfree(io_bitmap_a_region);
   }
   if(io_bitmap_b_region){
     printk("<1> freeing allocated io bitmapB region!\n");
     kfree(io_bitmap_b_region);
   }
   if(msr_bitmap_region){
     printk("<1> freeing allocated msr bitmap region!\n");
     kfree(msr_bitmap_region);
   }
   if(virtual_apic_page){
     printk("<1> freeing allocated virtual apic page region!\n");
     kfree(virtual_apic_page);
   }
}

static void save_registers(void){
   asm volatile("pushq %rcx\n"
           "pushq %rdx\n"
	   "pushq %rax\n"
	   "pushq %rbx\n"
          ); 

}

static void restore_registers(void){
     asm volatile("popq %rbx\n"
     	     "popq %rax\n"
             "popq %rdx\n"
	     "popq %rcx\n");

}

/*initialize revision id*/
static void vmxon_setup_revid(void){
   asm volatile ("mov %0, %%rcx\n"
       :
       : "m"(vmx_msr_addr)
       : "memory");

   asm volatile("rdmsr\n");

   asm volatile ("mov %%rax, %0\n"
       :
       :"m"(vmx_rev_id)
       :"memory");
}

/*turn on vmxe*/
static void turn_on_vmxe(void) {
   asm volatile("movq %cr4, %rax\n"
           "bts $13, %rax\n"
           "movq %rax, %cr4\n"
	  );
   printk("<1> turned on cr4.vmxe\n");
}

/*turn off vmxe*/
static void turn_off_vmxe(void) {
   asm volatile("movq %cr4, %rax\n"
           "btr $13, %rax\n"
           "movq %rax, %cr4\n"
	  );
   printk("<1> turned off cr4.vmxe\n");
}


/*do vmptrld*/
static void do_vmptrld(void) {
    asm volatile (MY_VMX_VMPTRLD_RAX 
		: : "a"(&vmcs_phy_region), "m"(vmcs_phy_region)
			: "cc", "memory");
     asm volatile("jbe vmptrld_fail\n");
     vmptrld_success = 1;
     asm volatile("jmp vmptrld_finish\n"
             "vmptrld_fail:\n"
              "pushfq\n"
            );
     asm volatile ("popq %0\n"
		   :
                   :"m"(rflags_value)
                   :"memory"
                   );
     vmptrld_success = 0;
     printk("<1> vmptrld has failed!\n");
     asm volatile("vmptrld_finish:\n");

}

/*do vmclear*/
static void do_vmclear(void) {
   asm volatile (MY_VMX_VMCLEAR_RAX 
		: : "a"(&vmcs_phy_region), "m"(vmcs_phy_region)
			: "cc", "memory");
     asm volatile("jbe vmclear_fail");
     vmclear_success = 1;
     asm volatile("jmp vmclear_finish\n"
     		  "vmclear_fail:\n"
     		  "pushfq\n"
                  );
     asm volatile ("popq %0\n"
		   :
                   :"m"(rflags_value)
                   :"memory"
                   );
     vmclear_success = 0;
     //printk("<1> rflags after vmclear: 0x%lx\n",rflags_value);
     //printk("<1> vmclear has failed!\n");
     asm volatile("vmclear_finish:\n");
     printk("<1> vmclear done!\n");
}



/*do vmxon*/
static void do_vmxon(void) {
   asm volatile (MY_VMX_VMXON_RAX
 	         : : "a"(&vmxon_phy_region), "m"(vmxon_phy_region)
		 : "memory", "cc");
   asm volatile("jbe vmxon_fail\n");
     vmxon_success = 1;
     asm volatile("jmp vmxon_finish\n"
             "vmxon_fail:\n"
              "pushfq\n"
            );
     asm volatile ("popq %0\n"
		   :
                   :"m"(rflags_value)
                   :"memory"
                   );
     vmxon_success = 0;
     printk("<1> vmxon has failed!\n");
     asm volatile("vmxon_finish:\n");
}

/*do vmxoff*/
static void do_vmxoff(void) {
   asm volatile ("vmxoff\n" : : : "cc");
   asm volatile("jbe vmxoff_fail\n");
   vmxoff_success = 1;
   asm volatile("jmp vmxoff_finish\n");
   asm volatile("vmxoff_fail:\n");
   vmxoff_success = 0;
   printk("<1> vmxoff has failed!\n");
   asm volatile("vmxoff_finish:\n");
   printk("<1> vmxoff complete\n");
}


static void vmxon_exit(void) {
   if(vmxon_success==1) {
     printk("<1> Machine in vmxon: Attempting vmxoff\n");
     do_vmxoff();
     vmxon_success = 0;
   }
   turn_off_vmxe();
   deallocate_vmcs_region();
   deallocate_vmxon_region();
}



static int vmxon_init(void) {
   unsigned long field_1;
   u32 value_1    =0;
   int cpuid_leaf =1;
   int cpuid_ecx  =0;
   int msr3a_value = 0;

   printk("<1> In vmxon\n");
   save_registers();

   asm volatile("cpuid\n\t"
       :"=c"(cpuid_ecx)
       :"a"(cpuid_leaf)
       :"%rbx","%rdx"); 

   if((cpuid_ecx>>CPUID_VMX_BIT)&1){
      printk("<1> VMX supported CPU.\n");
   } else {
      printk("<1> VMX not supported by CPU. Not doing anything\n");
      goto finish_here;
   }

  /*
   asm volatile ("mov %0, %%rcx\n"
       :
       : "m"(feature_control_msr_addr)
       : "memory"); */

   asm volatile("rdmsr\n"
                :"=a"(msr3a_value)
                :"c"(feature_control_msr_addr)
                :"%rdx"
               );

   if(msr3a_value&1){
     if((msr3a_value>>2)&1){
       printk("MSR 0x3A:Lock bit is on.VMXON bit is on.OK\n");
     } else {
       printk("MSR 0x3A:Lock bit is on.VMXONbit is off.Cannot do vmxon\n");
       goto finish_here;
     }
   } else {
      printk("MSR 0x3A: Lock bit is not on. Not doing anything\n");
      goto finish_here;
  }

   allocate_vmxon_region();

   if(vmxon_region==NULL){
      printk("<1> Error allocating vmxon region\n");
      vmxon_exit();
      vmxon_success = -ENOMEM;
      return vmxon_success;
   }

   vmxon_phy_region = __pa(vmxon_region);
   vmxon_setup_revid();
   memcpy(vmxon_region, &vmx_rev_id, 4); //copy revision id to vmxon region
   turn_on_vmxe();
   do_vmxon();
   allocate_vmcs_region();

   alloc_failure = (vmcs_guest_region==NULL) || (io_bitmap_a_region==NULL) || (io_bitmap_b_region==NULL) || (msr_bitmap_region==NULL) || (virtual_apic_page==NULL);

   if(alloc_failure){
      printk("<1> Error allocating vmcs guest region\n");
      vmxon_exit();
      vmptrld_success = -ENOMEM;
      return vmptrld_success;
   }
   vmcs_phy_region = __pa(vmcs_guest_region);
   memcpy(vmcs_guest_region, &vmx_rev_id, 4); //copy revision id to vmcs region
   do_vmptrld();
   initialize_guest_vmcs();

   // do_vmlaunch();
   //host rip
   asm ("movq $0x6c16, %rdx");
   asm ("movq $vmexit_handler, %rax");
   asm ("vmwrite %rax, %rdx");

   //guest rip
   asm ("movq $0x681e, %rdx");
   asm ("movq $guest_entry_point, %rax");
   asm ("vmwrite %rax, %rdx");

   printk("<1> Doing vmlaunch now..\n");
   asm volatile (MY_VMX_VMLAUNCH);
   asm volatile("jbe vmexit_handler\n");
   asm volatile("nop\n"); //will never get here
   asm volatile("guest_entry_point:");
   asm volatile(MY_VMX_VMCALL);
   asm volatile("ud2\n"); //will never get here
   asm volatile("vmexit_handler:\n");

   printk("<1> After vmexit\n");

   field_1 = VMX_EXIT_REASON;
   value_1 = do_vmread(field_1);
   printk("<1> Guest VMexit reason: 0x%x\n",value_1);

   vmxon_exit(); //do vmxoff
   printk("<1> Enable Interrupts\n");
   asm volatile("sti\n");
finish_here:
   printk("<1> Done\n");
   restore_registers();
   return 0;
}


static void vmxon_exit_dummy(void) {



}

module_init(vmxon_init);
module_exit(vmxon_exit_dummy);
