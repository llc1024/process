# 分析进程创建、执行、切换以及可执行文件的加载
学号241，姓名刘乐成，原创作品转载请注明出处 + [https://github.com/mengning/linuxkernel/](https://github.com/mengning/linuxkernel/)。

## 实验环境

VMware Workstation 14 Player虚拟机
Ubuntu 64位系统

## 实验目的

从整理上理解进程创建、可执行文件的加载和进程执行进程切换，重点理解分析fork、execve和进程切换

## 实验步骤

1、什么是进程？
<1> 进程是程序的一个执行实例
<2> 进程是正在执行的程序
<3> 进程是能分配处理器并由处理器执行的实体
为了管理进程，操作系统必须对每个进程所做的事情进行清楚的描述，为此，操作系统使用数据结构来代表处理不同的实体，这个数据结构就是通常所说的进程描述符或进程控制块（PCB）。
在linux操作系统下这就是task_struct结构 ，所属的头文件#include <sched.h>每个进程都会被分配一个task_struct结构，它包含了这个进程的所有信息，在任何时候操作系统都能够跟踪这个结构的信息。

2、分析fork函数对应的内核处理过程
do_fork代码如下：
```
long do_fork(unsigned long clone_flags,
          unsigned long stack_start,
          unsigned long stack_size,
          int __user *parent_tidptr,
          int __user *child_tidptr)
{
    struct task_struct *p;
    int trace = 0;
    long nr;

    // ...

    // 复制进程描述符，返回创建的task_struct的指针
    p = copy_process(clone_flags, stack_start, stack_size,
             child_tidptr, NULL, trace);

    if (!IS_ERR(p)) {
        struct completion vfork;
        struct pid *pid;

        trace_sched_process_fork(current, p);

        // 取出task结构体内的pid
        pid = get_task_pid(p, PIDTYPE_PID);
        nr = pid_vnr(pid);

        if (clone_flags & CLONE_PARENT_SETTID)
            put_user(nr, parent_tidptr);

        // 如果使用的是vfork，那么必须采用某种完成机制，确保父进程后运行
        if (clone_flags & CLONE_VFORK) {
            p->vfork_done = &vfork;
            init_completion(&vfork);
            get_task_struct(p);
        }

        // 将子进程添加到调度器的队列，使得子进程有机会获得CPU
        wake_up_new_task(p);

        // ...

        // 如果设置了 CLONE_VFORK 则将父进程插入等待队列，并挂起父进程直到子进程释放自己的内存空间
        // 保证子进程优先于父进程运行
        if (clone_flags & CLONE_VFORK) {
            if (!wait_for_vfork_done(p, &vfork))
                ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, pid);
        }

        put_pid(pid);
    } else {
        nr = PTR_ERR(p);
    }
    return nr;
}
```

3、使用gdb跟踪分析一个fork系统调用内核处理函数do_fork
编译
```
rm menu -rf
git clone https://github.com/mengning/menu.git
cd menu
mv test_fork.c test.c
make rootfs
```
打开gdb进行调试，并设置断点

```
b sys_clone
b _do_fork
b dup_task_struct
b copy_process
```
![设置](https://github.com/llc1024/process/blob/master/TIM%E6%88%AA%E5%9B%BE20190325213513.png)

最终结果

![结果](https://github.com/llc1024/process/blob/master/TIM%E6%88%AA%E5%9B%BE20190325214134.png)

4、理解编译链接的过程和ELF可执行文件格式

动态链接库(Dynamic Linked Library)：
Windows为应用程序提供了丰富的函数调用，这些函数调用都包含在动态链接库中。其中有3个最重要的DLL，Kernel32.dll，它包含用于管理内存、进程和线程的各个函数；User32.dll，它包含用于执行用户界面任务(如窗口的创建和消息的传送)的各个函数；GDI32.dll，它包含用于画图和显示文本的各个函数。

静态库(Static Library)：
函数和数据被编译进一个二进制文件(通常扩展名为.LIB)。在使用静态库的情况下，在编译链接可执行文件时，链接器从库中复制这些函数和数据并把它们和应用程序的其它模块组合起来创建最终的可执行文件(.EXE文件)。

## 实验总结
通过系统调用，用户空间的应用程序就会进入内核空间，由内核代表该进程运行于内核空间，这就涉及到上下文的切换，用户空间和内核空间具有不同的地址映射，通用或专用的寄存器组，而用户空间的进程要传递很多变量、参数给内核，内核也要保存用户进程的一些寄存器、变量等，以便系统调用结束后回到用户空间继续执行，所谓的进程上下文，就是一个进程在执行的时候，CPU的所有寄存器中的值、进程的状态以及堆栈中的内容，当内核需要切换到另一个进程时，它需要保存当前进程的所有状态，即保存当前进程的进程上下文，以便再次执行该进程时，能够恢复切换时的状态，继续执行。
同理，硬件通过触发信号，导致内核调用中断处理程序，进入内核空间。这个过程中，硬件的一些变量和参数也要传递给内核，内核通过这些参数进行中断处理，中断上下文就可以理解为硬件传递过来的这些参数和内核需要保存的一些环境，主要是被中断的进程的环境。
