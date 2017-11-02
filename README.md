## 依赖
1. 编译需要`cmake`和`g++`
1. 运行需要`libcrafter`，安装方式见  https://github.com/pellegre/libcrafter

## 使用
现在已存在的收集数据函数均在`metrics.c`中,返回值类型为`g_val_t`,是各个变量类型的union,可扩展.
添加新的收集源可以在`metrics.c`中补充新的函数,并在`conf.c`中补充进`callback_options`列表,之后再配置文件中配置该数据.

##程序流程

1. 验证用户名密码
2. 创建tcp_accrpt_thread,等待接收安全策略或其他数据
3. 每个`collection_group`开启一个线程,做数据的收集与发送

## 配置文件格式

服务端host与port
```json
"tcp_client_channel": {
    "host": "127.0.0.1",
    "port": 8650
},
```

接收安全策略port
```json
"tcp_accept_channel": {
    "port": 8649
},
```

所要收集的数据,每个object是一个线程
```json
"collection_group": {
    "device": [
        {"name": "mem_total", "collect_every": 40},
        {"name": "mem_free", "collect_every": 40},
        {"name": "mem_shared", "collect_every": 40},
        {"name": "mem_buffers", "collect_every": 40},
        {"name": "mem_cached", "collect_every": 40},
        {"name": "swap_free", "collect_every": 40}
    ],
    "net": [
        {"name": "ip_test", "collect_every": 20}
    ]
}
```

数值类数据不需要展示存入rrd数据库的置0
```json
"is_in_rrd": {
    "boottime": 0
},
```