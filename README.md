<img src="docs/logo.png" alt="secGear" style="zoom:100%;" />

## Summer2021-No46.使用secGear机密计算框架保护openssh的落盘口令

## 介绍

https://gitee.com/openeuler-competition/summer-2021/issues/I3EGZ9

改造openssh，利用secGear对秘钥进行加密，让数据和数据处理流程都在机密计算的可信执行环境当中。

## 安装教程

1. 下载openEuler-20.03-LTS-SP2-x86_64-dvd.iso，挂载openEuler-20.03-LTS-SP2-everything-x86_64-dvd.iso

2. 修改网卡信息和路由

3. ```
   yum install secGear linux-sgx-driver intel-sgx-ssl
   //安装sgx driver
   sudo /sbin/depmod
   sudo /sbin/modprobe isgx
   yum install cmake gcc-c++ openssl-devel secgear-devel intel-sgx-ssl-devel ocaml-dune
   ```

## 使用说明

```
make debug
cd debug
source ../environment
cmake -DCMAKE_BUILD_TYPE=Debug -DCC_SGX=ON -DSGXSDK=/opt/intel/sgxsdk -DCC_SIM=ON -DENCLAVE_SSL=/opt/intel/sgxssl ../ 
make 
make install
cd bin
./secgear_opensshDemo
```

