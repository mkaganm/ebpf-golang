# bpftrace Örnekleri

## Dosya Açma Takibi

```bpftrace
kprobe:do_sys_open {
    printf("%s %s\n", comm, str(arg1));
}
```

## Fonksiyon Süresi Ölçümü

```bpftrace
uprobe:/usr/bin/myapp:myfunc
{
    @start[tid] = nsecs;
}
uretprobe:/usr/bin/myapp:myfunc
{
    printf("Süre: %d ns\n", nsecs - @start[tid]);
    delete(@start[tid]);
}
```
