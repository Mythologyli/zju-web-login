# ZJU Web Login / ZJU 网页认证登录脚本

用于 ZJUWLAN/LAN 网页认证登录/登出

## 致谢

原作者：[Azuk 443](https://azuk.top/)

原发布地址：[新 ZJUWLAN 登录脚本](https://www.cc98.org/topic/4898875)

经原作者授权，在原脚本基础上修复登出功能后发布

## 使用方法

### 登录

#### 不指定登录 IP

```bash
python3 weblogin.py login -u <username> -p <password>
```

#### 指定登录 IP

```bash
python3 weblogin.py login -u <username> -p <password> -i <ip>
```

#### 指定登录 URL

```bash
python3 weblogin.py login -u <username> -p <password> -u "https://net2.zju.edu.cn"
```

### 登出

#### 不指定登出 IP

```bash
python3 weblogin.py logout -u <username>
```

#### 指定登出 IP

```bash
python3 weblogin.py logout -u <username> -i <ip>
```

#### 指定登出 URL

```bash
python3 weblogin.py logout -u <username> -u "https://net2.zju.edu.cn"
```