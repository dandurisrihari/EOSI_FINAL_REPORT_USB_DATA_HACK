#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include<linux/string.h>
#include<linux/kprobes.h>
#include<linux/kallsyms.h>
#include<linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <asm/uaccess.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>

#include "header.h"

static dev_t first; // Global variable for the first device number
static struct cdev c_dev; // Global variable for the character device structure
static struct class *cl; // Global variable for the device class

static int device_counter=1;
static  char password[20];
struct kprobe pen_drive_in_kp;
static void dump_state(struct pt_regs *regs);

struct list_head all_usb_data_list = LIST_HEAD_INIT(all_usb_data_list);



struct all_usb_data {
    int device_no;
    struct pt_regs *regs;
    struct usb_interface *intf;
    struct list_head dlist;
};



//WHEN PENDRIVE IS INSERTED THIS FUNCTION IS EXECUTED
static int PEN_DRIVE_PROBE_FUN(struct usb_interface *interface)
{

   struct usb_host_interface *interface_descriptor;
    struct usb_endpoint_descriptor *endpoint;
    int i;

    interface_descriptor = interface->cur_altsetting;
    printk(KERN_INFO "PEN DRIVE %d IS PROBED:\n",
            interface_descriptor->desc.bInterfaceNumber);
    printk(KERN_INFO "USBID->bNumEndpoints: %02X\n",
            interface_descriptor->desc.bNumEndpoints);
    printk(KERN_INFO "USBID->bInterfaceClass: %02X\n",
            interface_descriptor->desc.bInterfaceClass);

    for (i = 0; i < interface_descriptor->desc.bNumEndpoints; i++)
    {
        endpoint = &interface_descriptor->endpoint[i].desc;

        printk(KERN_INFO "USBED[%d]->bEndpointAddress: 0x%02X\n",
                i, endpoint->bEndpointAddress);
        printk(KERN_INFO "USBED[%d]->bmAttributes: 0x%02X\n",
                i, endpoint->bmAttributes);
        printk(KERN_INFO "USBED[%d]->wMaxPacketSize: 0x%04X (%d)\n",
                i, endpoint->wMaxPacketSize,
                endpoint->wMaxPacketSize);
    }


    return 0;
}




static ssize_t my_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
    printk(KERN_INFO "password entered is %s \n",password);
    if(strcmp(password,"haiihari")==0){
        struct all_usb_data* iter= NULL;
        struct all_usb_data* next= NULL;
        printk(KERN_INFO "Driver: read()\n");
            //iterating over list
        list_for_each_entry_safe(iter,next,&all_usb_data_list,dlist){
            printk("Devie number is %d",iter->device_no);
            PEN_DRIVE_PROBE_FUN(iter->intf);
            dump_state(iter->regs);

        }
    }
    return 0;
}


static ssize_t my_write(struct file *f, const char __user *buf, size_t len,loff_t *off)
{
    printk(KERN_INFO "Driver: write()\n");
    copy_from_user((void *)&password,(const void __user *)buf,sizeof(password));
    return len;
}


static struct file_operations pugs_fops =
{
    .owner = THIS_MODULE,
    .read = my_read,
    .write = my_write,
};


static void dump_state(struct pt_regs *regs)
{
    print_symbol(KERN_INFO "EIP is at %s\n", regs->ip);
    printk(KERN_INFO "eax: %08lx   ebx: %08lx   ecx: %08lx   edx: %08lx\n", regs->ax, regs->bx, regs->cx, regs->dx);
    printk(KERN_INFO "esi: %08lx   edi: %08lx   ebp: %08lx   esp: %08lx\n", regs->si, regs->di, regs->bp, regs->sp);
}

static void regs_cpy(struct pt_regs *regs_source,struct pt_regs *regs_destination){

    regs_destination->ip = regs_source->ip;
    regs_destination->ax = regs_source->ax;
    regs_destination->bx = regs_source->bx;
    regs_destination->cx = regs_source->cx;
    regs_destination->dx = regs_source->dx;
    regs_destination->si = regs_source->si;
    regs_destination->di = regs_source->di;
    regs_destination->bp = regs_source->bp;
    regs_destination->sp = regs_source->sp;

}

int Pre_Handler(struct kprobe *kp, struct pt_regs *regs){

    struct all_usb_data *per_dev_node;
    char address[20];
    struct us_data *us;
    unsigned int adder;

    struct usb_interface **temp;
    printk(KERN_INFO "INSIDE PRE HANDLER\n");


    per_dev_node = (struct all_usb_data *)kmalloc(sizeof(struct all_usb_data), GFP_KERNEL);
    per_dev_node->regs = (struct pt_regs *)kmalloc(sizeof(struct pt_regs), GFP_KERNEL);
    per_dev_node->intf = (struct usb_interface *)kmalloc(sizeof(struct usb_interface), GFP_KERNEL);


    per_dev_node->device_no=device_counter++;

    sprintf(address,"%08lx",regs->si);

    printk(KERN_INFO"address is %08lx\n",regs->sp);

    //per_dev_node->intf=(struct usb_interface *)address;
    per_dev_node->intf=(struct usb_interface *)address;
   //memcpy(per_dev_node->intf,(struct usb_interface *)address,sizeof(struct usb_interface));

    //us = usb_get_intfdata(*temp);
    printk(KERN_INFO "bNumEndpoints is %d",per_dev_node->intf->cur_altsetting->desc.bNumEndpoints );


   // memset((void *)address, 0, sizeof(address));

    regs_cpy(regs,per_dev_node->regs);
    list_add(&per_dev_node->dlist, &all_usb_data_list);
    return 0;

}


static int __init pen_init(void)
{

    int ret;
    struct device *dev_ret;
    unsigned long int pre_hand_address=0;

    printk(KERN_INFO "Registered character device \n");
    if ((ret = alloc_chrdev_region(&first, 0, 1, "sri_hari")) < 0)
    {
        return ret;
    }
    if (IS_ERR(cl = class_create(THIS_MODULE, "chardrv")))
    {
        unregister_chrdev_region(first, 1);
        return PTR_ERR(cl);
    }
    if (IS_ERR(dev_ret = device_create(cl, NULL, first, NULL, "USB_hacked_data")))
    {
        class_destroy(cl);
        unregister_chrdev_region(first, 1);
        return PTR_ERR(dev_ret);
    }

    cdev_init(&c_dev, &pugs_fops);
    if ((ret = cdev_add(&c_dev, first, 1)) < 0)
    {
        device_destroy(cl, first);
        class_destroy(cl);
        unregister_chrdev_region(first, 1);
        return ret;
    }

    pre_hand_address = kallsyms_lookup_name("usb_stor_disconnect"); 

    if(pre_hand_address == 0){  
        printk(KERN_INFO "usb_stor_probe2 SYMBOL NOT FOUND\n");
        return -EINVAL;
    }

    pen_drive_in_kp.pre_handler=Pre_Handler;
    pen_drive_in_kp.addr=(kprobe_opcode_t *)pre_hand_address;
    printk(KERN_INFO "REGISTERING KPROBE AT ADDRESS %p\n", (void*)(pre_hand_address));

    // register the exit krpobe
    if(register_kprobe(&pen_drive_in_kp)){
        printk(KERN_INFO "ERROR WHILE KEEPING KPROBE AT usb_stor_probe1  %p\n", (void*)(pre_hand_address));
        return -EINVAL;
    }
    return 0;
}

static void __exit pen_exit(void)
{
    struct all_usb_data* iter= NULL;
    struct all_usb_data* next= NULL;
    cdev_del(&c_dev);
    device_destroy(cl, first);
    class_destroy(cl);
    unregister_chrdev_region(first, 1);
    printk(KERN_INFO "unregistered character device\n");
    unregister_kprobe(&pen_drive_in_kp);

     //iterating over list
    list_for_each_entry_safe(iter,next,&all_usb_data_list,dlist){
        kfree(iter);
    }

}

module_init(pen_init);
module_exit(pen_exit);
MODULE_LICENSE("GPL");
