# Capability management based on PAM

这是国科大操作系统安全的课程实验，本仓库实现了基于PAM的用户权能分配，通过构建一个能够管理权能的模块，可以在用户登陆时对指定文件分配或收回权能。

## 构造

首先需要安装`libcap`库和`libpam`库，

- ​	对于Arch Linux:

```bash
sudo pacman -S libcap pam
```

- ​	对于Ubuntu:

```bash
sudo apt install libpam0g-dev libcap-dev
```

然后build本项目:

```bash
git clone https://github.com/SunYvming/cap-base-pam.git
cd cap-base-pam
make
```

安装本项目:对于默认的PAM位置

```bash
sudo make install
```

（卸载本项目）

```bash
sudo make uninstall
```

## 配置

- 首先需要将模块的认证插入到目标行为中，例如：对于登陆行为，相应的配置文件为`/etc/pam.d/system-login`;对于切换用户行为——也即`su target-user `，相应的配置文件为`/etc/pam.d/su`。

	这里对配置`su`进行演示

	```shell
    #%PAM-1.0
    auth            sufficient      pam_rootok.so
    # Uncomment the following line to implicitly trust users in the "wheel" group.
    #auth           sufficient      pam_wheel.so trust use_uid
    # Uncomment the following line to require a user to be in the "wheel" group.
    #auth           required        pam_wheel.so use_uid
	
	
    auth            required        pam_unix.so
    account         required        pam_unix.so
    session	        required        pam_unix.so
    session         include         login-cap
    password        include         system-auth
  ```

	login-cap项被插入到session pam_unix.so后，也可以将其插入到其之前。

- 然后对`/etc/pam.d/login-cap`进行配置，此文件是本项目模块的配置文件。在`session    optional   pam_ucas_cap.so`行后附加
	```shell
	user=testuser,file=/usr/bin/arping,+CAP_NET_RAW
	```
	其中`user`项代表模块进行操作的目标用户，如果此项为`*`则代表对所有用户进行操作。`file`项分两部分，首先是指定目标文件，示例配置中为`/user/bin/arping`;第二部分为目标权能，`+`号代表添加，`-`号代表删除，可以同时操作多个权能，权能间使用`,`隔开。

	可以同时对多个文件进行操作，每一项配置间用空格隔开，注意**单一配置内不要出现空格**。

## 使用

首先可以使用`getcap /bin/arping`查看此文件的权能，默认情况下此文件应没有任何权能。此时此文件需要root权限执行。

切换到目标用户查看配置是否成功：

```bash
su testuser
# 查看权能
getcap /bin/arping
# 试验该文件此时是否能执行
arping 192.168.50.130 # 这里应该是另一台机器的ip
```

退出用户，查看权能是否恢复：

```bash
exit
getcap /bin/arping
```

查看模块运行时日志：

```bash
journalctl | grep pam-login-cap
```



