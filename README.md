# DBScanner

自动扫描内网常见sql、no-sql数据库脚本未授权访问及常规弱口令检测
* mysql（扫描root账号弱口令）
* mssql（扫描sa账号弱口令）
* oracle（扫描system/sys/scott等账号弱口令）
* postgresql（扫描postgres账号弱口令）
* redis（扫描弱口令及未授权访问）
* mongodb（扫描未授权访问）
* memcached（扫描未授权访问）
* elasticsearch（扫描未授权访问）
* hadoop（扫描未授权访问）
* zookeeper（扫描未授权访问）


## 参数
```
  -h, --help  显示帮助文件
  -i IP       扫描IP或IP段
  -f FILE     IP清单文件
  -t THREAD   线程数(默认50)
```

## 使用方法
使用Python2运行
```
python dbscan.py -f iplist.txt
or
python dbscan.py -i 192.168.1.0/24  
```


![](https://github.com/Shad0wpf/DBScanner/blob/master/scan.png?raw=true)
