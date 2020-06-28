# Anti_GameAssist(反游戏外挂工具)
接下来简单介绍一下，这款工具的使用及实现
# 前言
现如今，游戏辅助工具横行霸道，严重损害了游戏的公平性，那么就非常有必要开发一款反游戏外挂工具。该工具是使用MFC开发而成，操作界面简洁易懂，在使用的过程中，需要选中PE文件和运行进程才能对其进行操作。主要分为5个功能模块：保护call及数据、注入代码检测、HOOK检测、调式工具检测和多开检测、添加反调试。

![image](https://github.com/chenpan01/Anti_GameAssist/tree/master/images/1.png)
# call及数据保护模块介绍
## 使用介绍
１.选择要保护的PE文件，选择后，在左边栏可以看到该该PE文件中含有的函数及全局数据地址。可以根据需要往右边栏添加要保护的数据和函数。
![image](https://github.com/chenpan01/Anti_GameAssist/tree/master/images/2.png)
２.点击保护时，该工具会在PE文件中修改调用函数的地址和使用数据的地址，修改后意味着如果直接执行该PE文件将不能正常运行，需要点击运行才能正常运行。这样就可以起到反调式的作用和混淆静态分析的作用。
![image](https://github.com/chenpan01/Anti_GameAssist/tree/master/images/3.png)
## 功能实现介绍
１.选中PE文件时，触发OnEnChangeMfceditbrowse事件，使用fopen函数读取PE文件，ftell函数读取PE文件大小，利用malloc在内存中分配同等大小内存，把文件信息赋值到内存中。

２.接着遍历PE文件中的代码段，找到函数头部，把地址转换成虚拟地址，在列表中显示出来。

３.又遍历代码段，通过硬编码找到mov指令，并判断后面接的操作数是否为在数据段的地址，若是，则为全局变量，显示在列表中。

4.点击执行保护时，对于函数，会找到调用该函数的call指令，并把call后接地址进行修改；对于数据，直接在列表中记录的地址处修改该数据地址。随后使用fopen和fwrite函数把内存中的PE文件写入到磁盘中

5.执行运行时，使用CreateProcess函数创建线程并悬挂，然后修改回内存中数据并运行进程。

# 代码检测模块介绍
该模块进行两个方面的校验：一个是动态校验、另一个是静态校验；
## 使用介绍
1.上面第一个文件选择框，用来计算PE文件校验值，第二个文件选择框用来校验给文件是否被修改，如果修改，则会弹出文件修改提示信息。

![image](https://github.com/chenpan01/Anti_GameAssist/tree/master/images/4.png)

2.下面的列表显示了，当前正在运行的进程，在该列表中选中，需要校验的进程，点击执行校验会校验该PE在运行时，内存是否已被修改，若被修改则会弹出提示框。

![image](https://github.com/chenpan01/Anti_GameAssist/tree/master/images/5.png)

3.选中进程文件，点击导出日志文件时，会把进程运行时，调用的函数信息会导入到一个日志文件中。

![image](https://github.com/chenpan01/Anti_GameAssist/tree/master/images/6.png)
## 功能实现介绍
1.选择PE文件计算文件校验值时，获取文件路径，使用MD5算法计算文件的静态校验值和动态校验值 。

2.选择需要静态校验的文件时，同样也使用MD５算法计算校验值，然后比较前后两次的校验值，如果不等，则已修改，否则没有修改。

３.当选择进程进行校验时，会遍历该进程的代码段并把代码段的信息导入到磁盘中，然后使用MD５加密算法算出校验值并比较是否修改

４.当点击导出日志文件时，使用DebugActiveProcess函数调式进程，接着创建一个线程，该线程接受调式事件，当创建调试时，会把用户自定义函数的头部修改为CC；当发生中断事件时，判断是否在用户自定义函数头部发生，若是，则记录在日志文件中。

# HOOk检测模块介绍
## 使用介绍
1.选中运行进程和选择进程运行时使用的dll(不含系统盘下的dll)所在的文件夹，点击检测dll注入，就可以检测是否有dll注入。

![image](https://github.com/chenpan01/Anti_GameAssist/tree/master/images/7.png)
2.选择进程和PE文件，点击IAT HOOK检测和Inline Hook检测，可以检测运行的进程是否有IAT HOOK或者Inline Hook。

![image](https://github.com/chenpan01/Anti_GameAssist/tree/master/images/8.png)
## 功能实现介绍
１.点击选择dll文件所在的文件夹，递归遍历该文件夹下所有的dll文件并把dll文件名存储到list容器中，点击检测dll注入时，会遍历该进程中使用的所有dll，找出是否有list容器中不存在的dll，若有，则说明有dll导入。

2.选中进程和PE文件后，当点击IAT HOOK检测时，会读取PE文件信息并把该PE文件中的IAT表信息存放在数组中。接着读取进程内存信息，同样读取进程内存中的IAT表信息，随后进行比较，不同则有IAT HOOK。

3.点击Inline Hook检测时，遍历PE文件代码段，记录用户自定义函数的开始和结束位置，接着遍历进程内存中的代码段，若发现用户定义函数内部存在跳出本函数的跳转指令，则可以判断该函数内存在Inline Hook。

# 工具和多开检测模块
## 使用介绍
1.选择进程，点击多开检测，就能检测该进程是否多开。

![image](https://github.com/chenpan01/Anti_GameAssist/tree/master/images/9.png)
2.选择进程和调式工具后，点击工具检测，就能检测是否有动态调式工具在调式它。

![image](https://github.com/chenpan01/Anti_GameAssist/tree/master/images/10.png)
## 功能实现介绍
1.选好进程，点击多开检测时，读取内存代码段信息，并存放在数组中，随后遍历所有进程，判断是否有代码段信息相同的进程；接着遍历判断是否有进程名相同的进程名，和窗口标题相同的进程。

2.选好工具，点击工具检测时，读取进程内存代码段信息，并寻找是否该工具是否正在运行，若在运行，则判断该工具的子进程是否为已选进程，若是，则表明工具正在调式该进程。

# 反调试模块介绍
## 使用介绍
1.选择需要添加，反调试的PE文件，点击相应的按钮，就能对该PE文件添加相应的反调试功能。

![image](https://github.com/chenpan01/Anti_GameAssist/tree/master/images/11.png)
## 功能实现介绍
1.点击添加SEH反调试时，读取该PE文件信息，并存放到内存中，在PE文件末尾添加SEH反调试代码，修改程序OEP地址，使PE文件运行时，能跳转到反调试代码中，如果程序没有处在调式状态中，则调回原OEP地址，否则调用ExitProcess结束进程。

2.点击TLS反调试时，同样把PE文件信息存放到内存中，修改TLS目录信息，使最后一个节表大小增大FileSection，在文件末尾添加TLS结构信息和TLS回调函数地址，及回调函数所有代码，回调函数中存在着判断进程是否处于调式状态的代码。
