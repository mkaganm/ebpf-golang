# bpftrace Examples

## File Open Tracking

```bpftrace
kprobe:do_sys_open {
    printf("%s %s\n", comm, str(arg1));
}
```

## Function Duration Measurement

```bpftrace
uprobe:/usr/bin/myapp:myfunc
{
    @start[tid] = nsecs;
}
uretprobe:/usr/bin/myapp:myfunc
{
    printf("Duration: %d ns\n", nsecs - @start[tid]);
    delete(@start[tid]);
}
```
