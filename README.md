# cargs
cargs用于对命令行参数使用salsa20进行简单快速方便的加解密，只需要在任意cli程序main函数起始位置进行初始化，提供随机的key与加密使用的flag即可。
```
cargs.Init([]byte("cargsRandomKey"), "getarg")
```
注意此处的key在每次编译时尽量做到随机，可通过makefile实现

随后调用时通过`./main getarg --help`来生成--help的加密参数，然后将此加密参数作为./main的参数即可。
## 编译
```
go build -tags cargs //使用cargs
go build //不使用cargs
```

## 适用场景
- 自研工具的参数、用法隐藏（主要用途）
- 代理类工具的参数隐藏

一般情况下，建议生成加密参数时在本地执行，以避免flag的泄露（flag泄漏后相当于任何人都能生成任何参数，该库也就没有作用了），此外，程序基本的混淆加密也是必不可少的。