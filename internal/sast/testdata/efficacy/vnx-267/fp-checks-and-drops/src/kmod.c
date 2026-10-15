static long dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (!ns_capable(current_user_ns(), CAP_SYS_PTRACE))
        return -EPERM;
    return 0;
}
