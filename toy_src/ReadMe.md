# 如何编译代码?

将本目录拷贝到你的 **linux** 系统下,然后在本目录下,执行 `make` 命令即可.

如果运行不能运行该程序,出现

```shell
Cannot open TUN/TAP dev, Make sure one exists with $ mknod /dev/net/tap c 10 200
```

的提示,那么你要执行命令:

```shell
% sudo mknod /dev/net/tap c 10 200
```

当然,这一条命令能够成功的前提是,你的 **linux** 系统有 **tun/tap** 模块.