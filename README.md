本程序是 Squad战术小队 服务端改票程序，用于服主和OP进行暖服。本程序无法单独使用，需要配合授权服务进行。

授权服务为免费授权，请联系QQ：1239996785

--------------------

服务器管理员使用步骤：

1.将该程序和Config.INI置入 \SquadGame\Binaries\Win64 内

2.编辑Config.INI填入相关信息，信息如下：
```
	SERVER_ID = 6d12de78566d46dc984c677db66bc654  //由验证方提供
	MEM_TOOL_ID = 564c50962a2e42bbab6b359a25516713   //由验证方提供
	SERVER_IP = 127.0.0.1  //对外IP
	MEM_TOOL_PORT = 9923  //对外开放端口
	VERSION = 1.0
	AUTH_SERVICE_URL = https://ticket-verify.squad.icu/heartbeat   //不需要改动
```

3.运行squad改票.exe文件

--------

服主用户使用步骤：

1. 服务器管理员将您的程序和Config.INI放置并运行好以后。

2. 通过访问https://ticket-verify.squad.icu/squad/get/ticket?team=[1或2]&key=[验证端提供的key] 进行查询team1和team2的票数
   通过访问https://ticket-verify.squad.icu/squad/set/ticket?team=[1或2]&value=[你要改的票数]&key=[验证端提供的key] 进行改票