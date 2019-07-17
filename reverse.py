import pefile
from capstone import *
import re

file_path = './3.exe'
pe = pefile.PE(file_path)
entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
image_base = pe.OPTIONAL_HEADER.ImageBase  # 找到解析好的 加载的基地址

def sort_(l):      #排序函数   字符串字典序排列  用于排call的函数
    if len(l) <= 1:
        return l
    mid = l[0]
    low = [item for item in l if item < mid]
    high = [item for item in l if item > mid]
    return sort_(low) + [mid] + sort_(high)


def get_call_list(list):  ##########输入解析完成后的pe文件   获取已经排过序的所有的 call_list
    call_list =[]
    function_list=[]
    main_=[]
    for i in list:
        if i[2] == "call":
            if i[3] not in call_list:
                call_list.append(i)     ####首先获得所有call list
        if i[0] == en_im:
            main_.append(i)

    row = len(call_list)

    list=[]
    call_range_list = []                #####切片获得函数顺序
    for i in range(row):
        list = str(call_list[i][3]).split("[")
        list = list[-1].split("]")
        call_range_list.append([list[0][2:], i])     ####获取切片后的函数

    call_range_list = sort_(call_range_list)#进行排序
    call_list_ranged = []                  #####根据排序存储call_list
    for i in call_range_list:
        call_list_ranged.append(call_list[i[1]])
    return call_list_ranged


def get_main_end_address(list,entrypoint,imagebase): ####获取函数的结束地址  输入list 和 起始地址，返回该函数的结束地址  使用栈平衡原理
    flag=0                                            ####输入参数  list：解析后的pe文件list     entrypoint：函数的起始地址     imagebase：文件基地址
    sum =0                                            ####输出参数  该函数的结束地址
    for i in list:
        if i[0]== str(hex(entrypoint+imagebase)):
            flag =1
        if flag==1 and i[2] =="push" and i[3] == "ebp":
            sum+=1
        if flag ==1 and i[2]=="pop" and i[3] =="ebp":
            sum -= 1
        if flag == 1 and sum ==0:
            return  i


def decode(code,image_base,address):          #####解析pe文件获得pe文件解析后的  list
    f = open("disassemble.txt","a")
    list =[]
    md = Cs(CS_ARCH_X86, CS_MODE_32)                # 我怎么确定  cpu的架构 和 编码模式
    for (address, size, mnemonic, op_str) in md.disasm_lite(code, image_base+address):
        f.write(str(hex(address))+" "+str(mnemonic)+" "+str(op_str)+"\n")
        list.append([hex(address), size, mnemonic, op_str])
    return list


def disame(file_path):   #####返回解析后的pe文件list   返回入口点 基址 相对虚拟地址的起点 main函数的结束地址
    pe = pefile.PE(file_path)            #直接使用函数读取 pe 文件
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    image_base = pe.OPTIONAL_HEADER.ImageBase    #找到解析好的 加载的基地址

    imported_functions ={}                     #使用了字典这种数据结构
    if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            for symbol in dll.imports:
                imported_functions[hex(symbol.address)] =symbol.name.decode()
    for section in pe.sections:
        address = section.VirtualAddress
        virtual_size = section.Misc_VirtualSize  # 问题出现在代码段的截取   我觉得这是pefile  所做工作 就是获得了虚拟内存的大小    怎么获得节表虚拟内存的大小  即在内存中的大小
        data = section.get_data()[:virtual_size]
        if(address<entrypoint and address+virtual_size>entrypoint):
            list = decode(data,image_base,address)
            main_end_address = get_main_end_address(list,entrypoint,image_base)

    return list,hex(entrypoint),hex(image_base),hex(entrypoint+image_base),main_end_address,imported_functions


def get_str2(va, text, text_virtual_address):  ####输入要提取的位置和要提取的节表
    str_ = ""                                   ####输入参数  va:跳转表所在的相对起始位置(VA)   text:跳转表所在的节表的二进制文件   text_virtual_address:跳转表所在节表的相对起始位置(VA)
    va = int(str(va), 16)
    while True:
        try:
            ch = text[va - text_virtual_address]  #####获取字符串所在的位置 #########我可以直接根据下标进行访问
        except:
            return ""
        if ch  in range(32, 127):###如果是可打印字符就直接打印
            ch_temp = chr(ch)
            str_+=ch_temp
        elif ch==0:        ###如果是字符串结束函数
            break
        else:
            return  ""
        va+=1
    return str_


def get_string(list,file_path):
    result = []
    pe = pefile.PE(file_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase  # 找到解析好的 加载的基地址
    p = re.compile(r'0x[0-9a-fA-F]+')  # 用于提取以0x开头的十六进制数
    for i in list:
        if i[2] =="push" and i[3][:2] =="0x":
            string = int(i[3],16) -image_base
            for section in pe.sections:
                address = section.VirtualAddress
                virtual_size = section.Misc_VirtualSize
                data = section.get_data()[:virtual_size]
                if (address< string and address + virtual_size> string):
                    s = get_str2(hex(string), data, address)
                    result.append(s)
    return result


def get_para_num(list,function_address):   ######输入list  获取参数个数  参数个数假设不可变    ######系统调用的函数   由系统自动释放    ######程序调用的函数   由调用程序出栈
    num_of_para={}                          ######获取函数调用的全局变量
    num_of_global = {}
    for i in range(len(list)):
        if list[i][2]=="add" and str(list[i][3]).find("esp")!=-1:
            if list[i-1][2]=="call" and str(list[i-1][3]).find("ptr")==-1:
                num_of_para[list[i-1][3]] = int(int(list[i][3][4:],16)/4)

    return num_of_para


def get_localvar_num(list,function_address): #####输入list   获取每个函数局部变量个数
    local_num={}
    for i in local_num:
        print(i)

    for i in list:
        if str(i[3]).find("ptr [ebp") !=-1:
            flag = 0
            for j in range(len(function_address)):
                if flag == 1:
                    break
                if j<len(function_address)-1:
                    if i[0]>function_address[j] and i[0]<function_address[j+1]:
                        # s = re.findall(r"ebp[\s\S]*",str(i[3]))
                        s= re.search('ptr \[ebp(.*?)\]',str(i[3]))
                        if s.group(0).find("*")==-1:
                            local_num.setdefault(function_address[j],[]).append(s)
                        flag=1
                        break
                elif i[0]>function_address[j]:
                    # s = re.search(r"ebp[\S]*?]$", str(i[3]))
                    s = re.search('ptr \[ebp(.*?)\]', str(i[3]))
                    if s.group(0).find("*") == -1:
                        local_num.setdefault(function_address[j], []).append(s)
                    flag = 1
                    break

    return local_num


def get_globalvar_num(list,function_address): #####输入list   获取每个函数局部变量个数
    local_num={}
    for i in local_num:
        print(i)

    for i in list:
        if str(i[3]).find("dword ptr [0x") !=-1 and  i[2]!="call":
            flag = 0
            for j in range(len(function_address)):
                if flag == 1:
                    break
                if j<len(function_address)-1:
                    if i[0]>function_address[j] and i[0]<function_address[j+1]:
                        # s = re.findall(r"ebp[\s\S]*",str(i[3]))
                        s= re.search('ptr \[(.*?)\]',str(i[3]))
                        if s.group(0).find("ebp")==-1 and s.group(0).find("*")==-1:
                            local_num.setdefault(function_address[j],[]).append(s.group(0))
                        flag=1
                        break
                elif i[0]>function_address[j] and s.group(0).find("*")==-1:
                    # s = re.search(r"ebp[\S]*?]$", str(i[3]))
                    s = re.search('ptr \[(.*?)\]', str(i[3]))
                    if s.group(0).find("ebp") == -1:
                        local_num.setdefault(function_address[j], []).append(s.group(0))
                    flag = 1
                    break
    return local_num


def get_list_dict(start,end):                                ######获取截取的整理过的字典  输入函数起始终止地址
    list_of_body=[]                                          ####输入参数:  函数的起始地址      函数的结束地址
    for i in list:
        if i[0] >= start and i[0] <= end:                   ####截取出函数汇编代码
            list_of_body.append(i)
            # print("233")
    list_dict = {}
    for i in list_of_body:
        list_dict[i[0]] = [i[2], i[3], i[1]]                ####获取主函数的以地址为key的字典
    return list_dict


def length_two(str):  #########对不足两位的数字进行补0 返回一个补0的i字符串
    while (len(str) < 2):
        str = '0' + str
    return str


def get_str(va, text, text_virtual_address):  ####输入要提取的位置和要提取的节表   提取出 switch case 的所有case
    ret = []                                  ####输入参数  va:跳转表所在的相对起始位置(VA)   text:跳转表所在的节表的二进制文件   text_virtual_address:跳转表所在节表的相对起始位置(VA)
    index = 0                                 ####返回值    switch的所有case的起始位置
    list = {}
    va = int(str(va), 16)
    while True:
        try:
            ch = text[va - text_virtual_address]  #####获取字符串所在的位置 #########我可以直接根据下标进行访问
        except:
            return ret
        list[index % 4] = ch
        if (index) % 4 == 3:
            # print(list[0], list[1], list[2], list[3])
            num = length_two(str(hex(list[3])[2:])) + length_two(str(hex(list[2])[2:])) + length_two(
                str(hex(list[1])[2:])) + length_two(str(hex(list[0])[2:]))
            if num[1]=='0':
                num = hex(int(num,16))
            if str(num) == "cccccccc" or (len(ret) > 0 and str(hex(int(num, 16))) < ret[-1]):
                break
            ret.append(str(hex(int(num, 16))))

        va += 1
        index += 1
    return ret


def get_node_start(list_dict):
    list_of_basenode_start=[]
    for i in list_dict:
        if str(list_dict[i][0]).find('jmp') != -1 and str(list_dict[i][1]).find('ptr') ==-1:                   ##如果是跳转又不是指针
            list_of_basenode_start.append(list_dict[i][1])                                                           ##直接存下跳转节点头
        elif str(list_dict[i][0]).find('j') != -1 and str(list_dict[i][1]).find('ptr') ==-1:                   ##如果发现了条件跳转
            list_of_basenode_start.append(list_dict[i][1])
        # print(i,int(i,16),i[2])
        #     list_of_basenode_start.append('To'+hex(int(i,16)+int(str(list_dict[i][2]),16)))
        elif str(list_dict[i][0]).find("jmp")!=-1 and str(list_dict[i][1]).find('ptr') !=-1:                   ##如果发现了 switch的语句
            string = str(list_dict[i][1])[-9:-1]
            string = int(string,16)-image_base
            for section in pe.sections:
                address = section.VirtualAddress
                virtual_size = section.Misc_VirtualSize
                data = section.get_data()[:virtual_size]
                if (address < string and address + virtual_size > string):
                    switch_case = get_str(hex(string),data,address)
                    for k in switch_case:
                        # print(k)
                        list_of_basenode_start.append(str(k))
    return  sort_(list_of_basenode_start)


def silce_of_list(list_dict,end,list_of_node_start):                                  ####划分基本段 输入划分好的字典
    for i in list_dict:                                      ##进行分段
        for j in list_dict:
            if j>=i  and (str(list_dict[j][0] ).find('jmp') != -1 or str(list_dict[j][0]).find('j') !=-1) or j == end:####如果遇见分段处 直接进行分段
                list_dict[i].append(j)
                break
            elif  j>=i  and hex(int(j,16)+int(str(list_dict[j][2]),16)) in list_of_node_start:
                list_dict[i].append(j)
                list_dict[i].append("To"+hex(int(j,16)+int(str(list_dict[j][2]),16)))


def store_for_node(list_dict):                                                        #######存储划分节点间边的关系
    switch_case=[]
    for i in list_dict:
        if str(list_dict[i][0]).find('jmp') != -1 and str(list_dict[i][1]).find('ptr') ==-1:                   ##如果是跳转又不是指针
            list_dict[i].append('To'+list_dict[i][1])                                                           ##直接存下跳转节点头
        elif str(list_dict[i][0]).find('j') != -1 and str(list_dict[i][1]).find('ptr') ==-1:                   ##如果发现了条件跳转
            list_dict[i].append('To'+list_dict[i][1])
        # print(i,int(i,16),i[2])
            list_dict[i].append('To'+hex(int(i,16)+int(str(list_dict[i][2]),16)))
        elif str(list_dict[i][0]).find("jmp")!=-1 and str(list_dict[i][1]).find('ptr') !=-1:                   ##如果发现了 switch的语句
            string = str(list_dict[i][1])[-9:-1]
            string = int(string,16)-image_base
            for section in pe.sections:
                address = section.VirtualAddress
                virtual_size = section.Misc_VirtualSize
                data = section.get_data()[:virtual_size]
                if (address < string and address + virtual_size > string):
                    switch_case = get_str(hex(string),data,address)
                    for k in switch_case:
                        # print(k)
                        list_dict[i].append('To' + str(k))


def get_node(list_dict):   # 提取节点之间的边  并进行排序
    node=[]
    end="0"
    for i in list_dict:                              # 输出函数关系
        if end != list_dict[i][3]:
            end =list_dict[i][3]
            list=[]
            for k in list_dict[list_dict[i][3]]:
                if str(k).find("To")!=-1:
                    list.append(k[2:])
            for j in list:
                # print(j)
                print("\""+str(i)+" "+str(list_dict[i][3])+"\"","->","\""+str(j)+" "+str(list_dict[j][3])+"\"")
                node.append(str(i)+str(list_dict[i][3]))
                node.append(str(j)+str(list_dict[j][3]))
    node = sort_(node)
    return node


def CFG_GET(start,end):
    list_dict = get_list_dict(start,end)                ###获得以地址为key存储的字典 用于后续操作
    list_of_node_start =get_node_start(list_dict)
    silce_of_list(list_dict,end,list_of_node_start)                             ###划分基本块   改变划分基本块的方法  再加一个条件  遇见jmp 等转移指令 或遇见基本块的起点就结束该基本块的划分
    store_for_node(list_dict)                            ###存储边的关系
    node = get_node(list_dict)                         ##提取边的关系


if __name__ == '__main__':
    # -------------------------反汇编代码在disame调用的decode函数里输出到disassemble.txt中------------------------------

    # ---------获取反汇编信息:pe文件list,入口点,基地址,en_im: 入口点+基地址,main函数的结束地址,导入表信息---------------
    list,entrypoint ,imagebase,en_im,main_end_address,imported_functions= disame(file_path)

    # ---------------------------------------------------获取call指令---------------------------------------------------
    call_ranged_list = get_call_list(list) #############获取所有的call指令
    # for i in call_ranged_list:
    #     print(i)

    # -------------------------------------------作为参数传递的字符串---------------------------------------------------
    result = get_string(list, file_path)
    # for item in result:
    #     print(item)

    # ---------------------------------------------挑选出内部函数-------------------------------------------------------
    call_list_address = []
    for i in call_ranged_list:  ##挑出所有内部函数
        if str(i).find("ptr") == -1:
            call_list_address.append(i[3])

    for i in range(len(call_list_address)):  # 插入主函数
        if i < len(call_list_address) - 1:
            if en_im > call_list_address[i] and en_im < call_list_address[i + 1]:
                call_list_address.insert(i + 1, en_im)
                break
        else:
            call_list_address.insert(len(call_list_address), str(en_im))
            break

    call_list_address_temp = set(call_list_address)  ##set集合没有排序
    call_list_address = []  ##插入后进行去重操作
    for i in call_list_address_temp:  ##去重会打乱顺序  需要再进行排序
        call_list_address.append(i)
    call_list_address = sort_(call_list_address)

    # ------------------------------------------函数参数个数------------------------------------------------------------
    num_of_para = get_para_num(list, call_list_address)
    # print(num_of_para)

    # -----------------------------------------各函数局部变量参数个数---------------------------------------------------
    num = get_localvar_num(list, call_list_address)  # 获得了初始的字符串匹配
    num_of_local = {}
    for i in num:
        for j in num[i]:
            # print(i,j.group(0))
            num_of_local.setdefault(i, []).append(j.group(0))

    for i in num_of_local:  # 进行去重操作
        # print(num_of_local[i])
        num_of_local[i] = set(num_of_local[i])
        # print(num_of_local[i])

    # for i in num_of_local:
    #     print(i, len(num_of_local[i]))
    #     for j in num_of_local[i]:
    #         print(i, j)
    # print(num_of_local)

    # ------------------------------------------各函数全局变量----------------------------------------------------------
    num_globalvar = get_globalvar_num(list, call_list_address)
    for i in num_globalvar:
        print(i, set(num_globalvar[i]))

    # -------------------------------------------------函数关系---------------------------------------------------------
    index = 0
    call_list_relation = {}
    for i in list:
        if i[2].find("call") != -1:  # 对其循环遍历进行存储
            flag = 0
            for j in range(len(call_list_address)):
                if flag == 1:
                    break
                if j < len(call_list_address) - 1:
                    for j in range(len(call_list_address) - 1):
                        if i[0] > call_list_address[j] and i[0] < call_list_address[j + 1]:
                            if call_list_address[j] not in call_list_relation.keys() or i[3] not in call_list_relation[call_list_address[j]]:
                                call_list_relation.setdefault(call_list_address[j], []).append(
                                    i[3])  # 一个 key 可以用多个 value
                                flag = 1
                                break  # 键值 value
                else:
                    if call_list_address[j] not in call_list_relation.keys() or i[3] not in call_list_relation[call_list_address[j]]:
                        call_list_relation.setdefault(call_list_address[j], []).append(
                            i[3])  # 一个 key 可以用多个 value
                        flag = 1
    # 添加完地址后进行去重操作
    for i in call_list_relation:
        for j in range(len(call_list_relation[i])):
            if str(call_list_relation[i][j]).find('ptr') != -1:
                for k in imported_functions:
                    if str(call_list_relation[i][j]).find(k) != -1:
                        call_list_relation[i][j] = imported_functions[k]
                        break

    # 把外部函数替换成函数名
    for i in call_list_relation:
        for j in call_list_relation[i]:
            if str(j).find('ptr') != -1:
                for k in imported_functions:
                    if str(j[0]).find(k) != -1:
                        j[0] = imported_functions[k]
                        break

    # 已经获得了函数的输出关系  需要打印出函数关系   输出函数的对应关系图
    # for i in call_list_relation:
    #     for j in call_list_relation[i]:
    #         print("function" + i, "->", "function" + j)

    # ------------------------------------------函数内部流程图----------------------------------------------------------
    for i in range(len(call_list_address)):
        end = get_main_end_address(list, int(call_list_address[i], 16), 0)
        if i < len(call_list_relation) - 1:
            if end[0] == None or end[0] > call_list_address[i + 1]:
                end = call_list_address[i + 1]
        else:
            if end[0] == None:
                end = call_list_address[i + 1]
        # print("**********************打印函数内部控制流图*******************************")
        # CFG_GET(call_list_address[i], end[0])





