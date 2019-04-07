### RSA加密登陆正方教务

1. 运行环境所需要的库rsa、bs4、requests
2. 登陆后可以使用cookie持续访问，具体操作，我就不在赘述了，每所学校也相同
3. 教务系统的url地址也不一定相同，具体通过浏览器确定url地址
   1. 登陆页面地址：获取crsftoken
   2. 获取公钥地址：获取公钥（modulus,exponent）
   3. 登陆请求发送地址：获取cookie
   4. 登陆后重定向地址：获取内容
4. RSA加密通过网页的js脚本生成，在python3中的算法感谢[EddieIvan01](https://github.com/EddieIvan01/analog-login.git)的分享

