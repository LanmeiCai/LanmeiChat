'''
addroomconfirm = {
    "用户A": {
        "群聊邀请": [
            {"#123": "(创建者:张三)欢迎加入群聊！"},
            {"#456": "(创建者:李四)技术交流群"}
        ]
    },
    "用户B": {
        "好友": [
            {"SZH": "我是孙正好"}
        ]
    },
    "张三": {
        "#123": [
            {"SZH": "我是孙正好，我想加群，同意一下"}
        ]
    }
}
'''

from flask import Flask,request,jsonify
from flask_cors import CORS
import os,re,secrets,ast
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64,time,json,random
from datetime import datetime ,timedelta
from binascii import Error as Base64Error
from binascii import hexlify
from threading import *
import hashlib
from collections import defaultdict
import time
write_lock = Lock()  # 在修改共享数据的地方加锁
read_lock = Lock()


# Initialize a dictionary to track IP requests
ip_request_count = defaultdict(list)


print('''
$$\                                                  $$\        $$$$$$\  $$\                  $$\     
$$ |                                                 \__|      $$  __$$\ $$ |                 $$ |    
$$ |      $$$$$$\  $$$$$$$\  $$$$$$\$$$$\   $$$$$$\  $$\       $$ /  \__|$$$$$$$\   $$$$$$\ $$$$$$\   
$$ |      \____$$\ $$  __$$\ $$  _$$  _$$\ $$  __$$\ $$ |      $$ |      $$  __$$\  \____$$\\_$$  _|  
$$ |      $$$$$$$ |$$ |  $$ |$$ / $$ / $$ |$$$$$$$$ |$$ |      $$ |      $$ |  $$ | $$$$$$$ | $$ |    
$$ |     $$  __$$ |$$ |  $$ |$$ | $$ | $$ |$$   ____|$$ |      $$ |  $$\ $$ |  $$ |$$  __$$ | $$ |$$\ 
$$$$$$$$\\$$$$$$$ |$$ |  $$ |$$ | $$ | $$ |\$$$$$$$\ $$ |      \$$$$$$  |$$ |  $$ |\$$$$$$$ | \$$$$  |
\________|\_______|\__|  \__|\__| \__| \__| \_______|\__|       \______/ \__|  \__| \_______|  \____/ 
                                                                                                      
                                                                                                      
                                                                                                      ''')
print("Lanmei chat server 20250801")
print("开发者：张蓝莓 摸鱼真菌不摸鱼 增稠剂")
timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
print("服务端重新启动：",timenow)
app = Flask(__name__)
CORS(app)


#字符合法性：只允许字母，中文，数字，空的直接false
def v(text):
    pattern = r'^[\u4e00-\u9fa5a-zA-Z0-9]+$' 
    return bool(re.match(pattern, text))


#LOG
'''
try:
    with open("log.txt", "r", encoding='utf-8') as file:
        logtxt = file.read()
except FileNotFoundError:
    timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 
    with open("log.txt", "w", encoding='utf-8') as file:
        file.write("【"+timenow+"】【LOG】创建完成！\n")
    print("【LOG】创建完成！")
except Exception as e:
    print(f"【LOG】读取log错误: {e}   此内容不会被log记录")
    time.sleep(5)
    os._exit(1)
'''
def Logx(x):
     timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
     #with open("log.txt", "a", encoding='utf-8') as file:
     #   file.write('【'+timenow+'】'+x+'\n')
     print('【'+timenow+'】'+x)

# DATA文件夹
if not os.path.exists('Data'):
    os.makedirs('Data')
    Logx('【DataSave】Data文件夹已创建')

# SHA-256
def toSHA256(x):
  pattern = r'^[\u4e00-\u9fa5a-zA-Z0-9]+$' 
  if re.match(pattern, x):
    if not isinstance(x, str):
        Logx("[ToSHA256] 转换错误！输入不是str类型" )
    sha256 = hashlib.sha256(x.encode('utf-8')).hexdigest()
    return sha256
  else:
      return "（错误）SHA256输入不合法"

# AES-256加密算法  iv:向量

try:
    with open("Data/key.txt", "r", encoding='utf-8') as file:
        lines=file.readlines()
        skey=bytes.fromhex(lines[0].strip())
        siv=bytes.fromhex(lines[1].strip())
        #print(KEY,IV)
except FileNotFoundError:
    Logx("【AES-256】找不到key.txt")
    time.sleep(5)
    os._exit(1)
except Exception as e:
    Logx(f"【AES-256】读取key.txt错误: {e}")
    time.sleep(5)
    os._exit(1)

KEY=secrets.token_bytes(32)
IV=secrets.token_bytes(16)#返回bytes格式

def encrypt(data: str) -> str:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    #print(os.linesep,"返回原始数据：",data,os.linesep,"加密后",base64.b64encode(encrypted).decode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def encryptkey(data: str) -> str:
    cipher = AES.new(skey, AES.MODE_CBC, siv)
    encrypted = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt(encrypted_data: str) -> str:
    """解密数据，自动处理可能的错误"""
    try:
        # 1. Base64 解码
        encrypted_bytes = base64.b64decode(encrypted_data)
        # 2. AES 解密
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        # 3. 去除填充
        plaintext = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
        return plaintext
    except Base64Error:
        return "（错误）无效的 Base64 编码"
    except ValueError as e:
        if "Padding is incorrect." in str(e):
            return "（错误）客户端会话密钥已过期，客户端请重启程序！"
        return f"（99错误）{str(e)}"
    except Exception as e:
        return f"（错误：解密失败）{str(e)}"


# 评价系统文件
ISSUE_FILE = "Data/issue.txt"

if not os.path.exists(ISSUE_FILE):
    with open(ISSUE_FILE, "w") as f:
        f.write("")


#List处理
userlist = {}
namelist = {}
userchatlist = {}
chatroomlist = {}
roommemberlist={}
addroomconfirm={}
deluser=""
delroom=""
def UserListSave():
    # 先写入临时文件
    temp_path = "Data/userlist.txt.tmp"
    with open(temp_path, "w", encoding='utf-8') as file:
        json.dump(userlist, file, ensure_ascii=False, indent=2)
        file.flush()
        os.fsync(file.fileno())
    
    # 原子操作替换原文件
    os.replace(temp_path, "Data/userlist.txt")
    
    print(userlist)

def NameListSave():
    with open("Data/namelist.txt", "w", encoding='utf-8') as file:
        json.dump(namelist, file, ensure_ascii=False, indent=2)
    print(namelist)

def UserChatListSave():
    with open("Data/userchatlist.txt", "w", encoding='utf-8') as file:
        json.dump(userchatlist, file, ensure_ascii=False, indent=2)
    print(userchatlist)

def ChatRoomListSave():
    with open("Data/chatroomlist.txt", "w", encoding='utf-8') as file:
        json.dump(chatroomlist, file, ensure_ascii=False, indent=2)
    print(chatroomlist)
        
def RoomMemberListSave():
    with open("Data/roommemberlist.txt", "w", encoding='utf-8') as file:
        json.dump(roommemberlist, file, ensure_ascii=False, indent=2)
    print(roommemberlist)
       
def ARCSave():  #AddRoomConfirm
    with open("Data/addroomconfirm.txt", "w", encoding='utf-8') as file:
        json.dump(addroomconfirm, file, ensure_ascii=False, indent=2)
    print(addroomconfirm)

# 尝试创建数据文件
def tryCreateFile(filename, default_content=None, is_json=False):
    try:
        if not os.path.exists(f"Data/{filename}.txt"):
            with open(f"Data/{filename}.txt", "w", encoding='utf-8') as file:
                if default_content is not None:
                    if is_json:
                        json.dump(default_content, file, ensure_ascii=False)
                    else:
                        file.write(default_content)
                else:
                    file.write("")
            Logx(f"【DATASAVE】{filename}创建完成！")
    except Exception as e:
        Logx(f"【DATASAVE】创建{filename}文件错误: {e}")

# 初始化数据文件
tryCreateFile("userlist", {"test": toSHA256("testpwd")}, True)
tryCreateFile("namelist", {"test": "测试"}, True)
tryCreateFile("userchatlist", {"test": ["#1"]}, True)
tryCreateFile("deleteduser", "")
tryCreateFile("chatroomlist", {"#1": "蓝莓通讯用户群"}, True)
tryCreateFile("roommemberlist", {"#1": ["test"]}, True)
tryCreateFile("addroomconfirm", {}, True)
tryCreateFile("deletedroom", "")

# 加载数据文件
def load_data():
  global userlist,namelist,userchatlist,deluser,chatroomlist,roommemberlist,addroomconfirm,delroom
  try:
   with write_lock: 
    with open("Data/userlist.txt", "r", encoding='utf-8') as file:
        userlist = json.load(file)
    with open("Data/namelist.txt", "r", encoding='utf-8') as file:
        namelist = json.load(file)
    with open("Data/userchatlist.txt", "r", encoding='utf-8') as file:
        userchatlist = json.load(file)
    with open("Data/deleteduser.txt", "r", encoding='utf-8') as file:
        deluser = file.read()
    with open("Data/chatroomlist.txt", "r", encoding='utf-8') as file:
        chatroomlist = json.load(file)
    with open("Data/roommemberlist.txt", "r", encoding='utf-8') as file:
        roommemberlist = json.load(file)
    with open("Data/addroomconfirm.txt", "r", encoding='utf-8') as file:
        addroomconfirm = json.load(file)
    with open("Data/deletedroom.txt", "r", encoding='utf-8') as file:
        delroom = file.read()
  except Exception as e:
    Logx(f"【DATASAVE】读取数据文件错误: {e}")
    time.sleep(5)
    os._exit(1)
load_data()


# Message文件夹及聊天记录保留
if not os.path.exists('Message'):
    os.makedirs('Message')
    Logx('【MessageSave】Message文件夹已创建')

# 修改 rum() 函数 - 确保写入完整性
def rum(rn, message):
    filename = "Message/Room#" + rn + ".txt"
    with write_lock:
        try:
            with open(filename, "a", encoding='utf-8') as file:
                file.write(f"{message}"+os.linesep)
            # 立即刷新缓冲区
            os.fsync(file.fileno())
        except Exception as e:
            Logx(f"【ERROR】消息存储失败: {e}")

def lat(rn, target_line_content):
    try:
      with read_lock:
        print("lat持有读取锁")
        filename = "Message/Room#" + rn + ".txt"  # 文件名称
        
        # 尝试解析格式化的消息
        try:
                if "：" in target_line_content and "【" in target_line_content and "】" in target_line_content:
                    # 分割发送者
                    sender_part, rest = target_line_content.split("：", 1)
                    # 从右侧找到最后一个【和】
                    last_left_bracket = rest.rfind("【")
                    last_right_bracket = rest.rfind("】")
            
                    if last_left_bracket < last_right_bracket:  # 确保【在】左侧
                        time = rest[last_left_bracket+1 : last_right_bracket]
                        sender = sender_part.strip()
                        message = rest[:last_left_bracket].strip()  # 排除时间部分
        except:
                sender = ""
                message = target_line_content
                time = ""
        
        with open(filename, 'r', encoding='utf-8') as file:
            lines = [line for line in file]  # 读取所有行
            
            if target_line_content.strip() == 'all':#传入 all返回所有
                return ''.join(lines)
            
            # 逆向查找包含目标内容的最后一行
            last_match_index = -1

            for i in range(len(lines)-1, -1, -1):  # 从最后一行开始向前查找
                if message == "": #撤回的消息没有消息内容
                    if time in lines[i].strip() and sender in lines[i].strip():  ##对于撤回的消息，使用模糊匹配，获取包含time和sender字段的最后一行
                        last_match_index = i
                        break
                else:
                    if target_line_content == lines[i].strip():  ##对于正常消息，使用精确匹配
                        last_match_index = i
                        break
            
            if last_match_index != -1:
                # 返回匹配行之后的所有行
                return ''.join(lines[last_match_index+1:])
            else:
                # 没有找到匹配行，返回全部内容
                return ''.join(lines)
        print("lat释放读取锁")        
    except FileNotFoundError:
        return ''
    except Exception as e:
        Logx(f"【DATASAVE】读取聊天记录错误: {e}")
        time.sleep(5)
        os._exit(1)

# 首先需要明确，客户端不能保存【**RECALL**】》原消息《【**RECALL**】,不然用户自己查txt文件就可以知道别人撤回了什么
# 所以，采用“发送人：【时间】”保存撤回的消息



def i30(message):#is_within_30_minutes
    try:
        #print('i30开始')
        time_str = message.split('【')[-1].split('】')[0]
        #print('i301:',time_str)
        message_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        #print("i302:",message_time)
    except (IndexError, ValueError):
        return False
    current_time = datetime.now()
    time_diff = current_time - message_time
    #print(time_diff)
    #print('i30结束')
    return time_diff <= timedelta(minutes=30) and time_diff >= timedelta(0)

def get_last_line(rn):
    try:
      with read_lock:
        print("gll持有读取锁")
        with open("Message/Room" + rn + ".txt", 'rb') as f:
            content = f.read()
            if not content:
                return '还没有消息！'
            
            # 统一换行符并解码
            content = content.replace(b'\r\n', b'\n').replace(b'\r', b'\n').decode('utf-8')
            lines = [line.strip() for line in content.split('\n') if line.strip()]
            
            # 收集所有被撤回的消息内容（不含撤回标记）
            recalled_messages = set()
            for line in lines:
                if "【**RECALL**】》" in line and "《【**RECALL**】" in line:
                    # 提取被撤回的原始消息
                    start = line.find("】》") + 2
                    end = line.find("《【")
                    if start != -1 and end != -1:
                        original_msg = line[start:end].strip()
                        recalled_messages.add(original_msg)
            
            # 从最后一行开始反向查找有效消息
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                
                # 跳过撤回标记行本身
                if "【**RECALL**】》" in line:
                    continue
                    
                # 检查是否是已被撤回的消息
                if line in recalled_messages:
                    return "【已撤回的内容】"
                else:
                    return line
                
            return '还没有消息！'
        print("gll释放读取锁")        
    except FileNotFoundError:
        return '还没有消息！'
    except Exception as e:
        print(f"获取最后一行错误: {e}")
        return '还没有消息！'


def jsondict(x):
    return json.dumps(x, ensure_ascii=False)


@app.route('/')
def root():
    return 'Lanmei chat server hello'

@app.route('/hello')
def getkey():
    a = encryptkey(hexlify(KEY).decode('utf-8'))
    b = encryptkey(hexlify(IV).decode('utf-8'))
    return f'["{a}","{b}"]'

@app.route('/key')
def getskey():
    return f'["{bytes.hex(skey)}","{bytes.hex(siv)}"]'

@app.route("/name")
def names():
    return encrypt(str(namelist))

@app.route('/signup', methods=['POST'])
def signup():
    # Get client IP address
    client_ip = request.remote_addr
    
    # Rate limiting check
    current_time = time.time()
    # Remove timestamps older than 1 hour
    ip_request_count[client_ip] = [t for t in ip_request_count[client_ip] if current_time - t < 3600]
    
    # Check if IP has made more than 10 requests in the last hour
    if len(ip_request_count[client_ip]) >= 10:
        result = encrypt('{"result":"请一小时后重试"}')
        Logx(f'【SIGNUP RATE LIMIT】IP {client_ip} 请求过于频繁')
        return result
    
    # Record this request
    ip_request_count[client_ip].append(current_time)
    
    # Original signup logic
    data = request.get_json()
    username = decrypt(data['username'])
    name = decrypt(data['name'])
    password = toSHA256(decrypt(data['password']))
    global userlist, namelist, userchatlist, roommemberlist
    timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    
    if v(username) and v(name) and v(password) and '错误' not in password:
        if username in userlist:
            result = encrypt('{"result":"'+username+'已被注册，所以注册失败！"}')
            Logx(f'【SIGNUP】{username}已被注册，所以注册失败！')
            return result
        else:
            with write_lock:
                userlist[username] = password
                namelist[username] = name
                userchatlist[username] = ["#1"]
                roommemberlist["#1"].append(username)
                RoomMemberListSave()
                UserListSave()
                NameListSave()
                UserChatListSave()
            result = encrypt('{"result":"success"}')
            Logx(f'【SIGNUP】{username}注册成功！')
            return result
    else:
        result = encrypt('{"result":"用户名、名称、密码只允许中文、数字、字母（中文密码也行）"}')
        Logx(f'【SIGNUP】{username}输入非法！')
        return result

@app.route('/login', methods=['POST'])
def login():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  global userlist, namelist,userchatlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password):
    if username not in userlist:
        result=encrypt('{"result":"账号或密码错误！"}')
        Logx(f'【LOGIN】{username}没注册，客户登录个蛋！')
        return result
    else:
        if password == userlist[username]:
            #print("login持有读取锁")
            rname=[]
            last_message={}
            for i in userchatlist[username]:
                rname.append(chatroomlist[i])
                last_message[i] = get_last_line(i)
            #print("login释放读取锁")
            result=encrypt(jsondict({
                "result": "success",
                "name":namelist[username],
                "userchatlist":userchatlist[username],
                "roomnamelist":rname,
                "recent_message":last_message,
                "ask":addroomconfirm.get(username,{})
            }))
            Logx(f'【LOGIN】{username}登录通过！')
            return result
        else:
            result=encrypt('{"result":"账号或密码错误！"}')
            Logx(f'【LOGIN】{username}密码错误！错误密码：{password}')
            return result
  else:
    result=encrypt('{"result":"用户名、名称、密码只允许中文、数字、字母（中文密码也行）"}')
    Logx(f'【LOGIN】{username}输入非法！')
    return result

@app.route('/logoff', methods=['POST'])
def logoff():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  global userlist, namelist,userchatlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and username != 'test':
    if username not in userlist:
        result=encrypt('{"result":"账号或密码错误"}')
        Logx(f'【LOGOFF】{username}没注册，客户注销个蛋！')
        return result
    else:
        if password == userlist[username]:
          with write_lock:
            deluser=jsondict({
                "time":timenow,
                "username":username,
                "password":userlist.pop(username,'不存在于userlist中'),
                "name":namelist.pop(username,'不存在于namelist中'),
                "addroomconfirm":addroomconfirm.pop(username,'不存在于addroomconfirm中'),
                "userchat":userchatlist.pop(username,'不存在于userchatlist中')})+os.linesep
            UserListSave()
            NameListSave()
            UserChatListSave()
            ARCSave()
            with open("Data/deleteduser.txt", "a", encoding='utf-8') as file:
                file.write(deluser)
                #print(deluser)
            #删除chatmemberlist中该用户
            print(os.linesep)
            keys_to_delete = []
            for room, members in roommemberlist.items():
                if username in members:
                    if members[0]==username:
                        if len(members)==1:
                            print(f'Room{room}的群主{username}注销，群聊删除')
                        else:
                            print(f'Room{room}的群主{username}注销，{members[1]}将成为新群主')
                    members.remove(username)
                    print(f'从Room{room}中移除了{username}')
                    if not members:
                        keys_to_delete.append(room)
            for room in keys_to_delete:
                del roommemberlist[room]
                print(f'删除了Room{room}')
            for room in keys_to_delete:
                del chatroomlist[room]
            RoomMemberListSave()
            ChatRoomListSave()#结束
          result=encrypt(jsondict({
                "result": "success",
          }))
          Logx(f'【LOGOFF】{username}注销完成，信息已记录！')
          return result
        else:
            result=encrypt('{"result":"账号或密码错误"}')
            Logx(f'【LOGOFF】{username}密码错误！错误密码：{password}')
            return result
  else:
    result=encrypt('{"result":"用户名、名称、密码只允许中文、数字、字母（中文密码也行）"}')
    Logx(f'【LOGOFF】{username}输入非法！')
    return result

@app.route('/getname/<username>')#请求username列表，返回name列表
def getname(username):
  global namelist
  ulist=ast.literal_eval(username)
  nlist=[]
  for u in ulist:
      if u in namelist:
          nlist.append(namelist[u])
      else:
          nlist.append('')
  return encrypt(str(nlist))

@app.route("/changename", methods=["POST"])
def changename():
    data = request.get_json()
    username = decrypt(data['username'])
    password = toSHA256(decrypt(data['password']))
    newname = decrypt(data['newname'])
    global userlist,namelist
    if not (v(username) and v(password) and v(newname)):
        result=encrypt('{"result":"用户名、房间名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
        Logx(f'【changename】输入非法！')
        return result
    if username not in userlist or userlist[username] != password:
        result=encrypt('{"result":"账号验证失败"}')
        Logx(f'【changename】账号验证失败！')
        return result
    with write_lock:
        namelist[username]=newname
        NameListSave()
    result=encrypt('{"result":"您已成功修改名称！"}')
    Logx(f'【changename】{username}已成功修改名称{newname}！')
    return result

@app.route("/changepwd", methods=["POST"])
def changepwd():
    data = request.get_json()
    username = decrypt(data['username'])
    password = toSHA256(decrypt(data['password']))
    newpwd = toSHA256(decrypt(data['newpwd']))
    global userlist
    if not (v(username) and v(password) and v(newpwd)):
        result=encrypt('{"result":"用户名、房间名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字，新密码可以与旧密码一致。"}')
        Logx(f'【changepwd】输入非法！')
        return result
    if username not in userlist or userlist[username] != password:
        result=encrypt('{"result":"账号验证失败"}')
        Logx(f'【changepwd】账号验证失败！')
        return result
    with write_lock:
        userlist[username]=newpwd
        UserListSave()
    result=encrypt('{"result":"您已成功修改密码！所有设备都需要重新登录！"}')
    Logx(f'【changename】{username}已成功修改密码！')
    return result

#聊天室管理
@app.route('/createroom' ,methods = ["POST"])
def createroom():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#","")
  roomname = decrypt(data['roomname'])
  intro = decrypt(data['introduction'])
  users = decrypt(data['users']).split(" ")
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit() and v(roomname):
    if username in userlist and userlist[username] == password :
      if "#"+roomnum in chatroomlist:
          result=encrypt('{"result":"房间号不可用"}')
          Logx(f'【CREATEROOM】Room#{roomnum}已存在，创建失败！')
          return result
      else:
        with write_lock:
          userchatlist[username].insert(0,"#"+roomnum)
          UserChatListSave()
          chatroomlist["#"+roomnum]=roomname
          ChatRoomListSave()
          roommemberlist["#"+roomnum]=[username]
          RoomMemberListSave()
          for i in users:
            if i not in roommemberlist["#"+roomnum] and i in userlist:
              if i not in addroomconfirm:
                  addroomconfirm[i]={}
              if "群聊邀请" not in addroomconfirm[i]:
                  addroomconfirm[i]["群聊邀请"]=[]
              new_invite = {"#" + roomnum: f"(创建者:{namelist[username]}){intro}"}
              if new_invite not in addroomconfirm[i]["群聊邀请"]:  # 检查是否已存在
                  addroomconfirm[i]["群聊邀请"].append(new_invite)
          ARCSave()
        rum(roomnum,f"**系统**：Room#{roomnum}由{namelist[username]}({username})创建完成！【{timenow}】")
        result=encrypt('{"result":"创建成功！您已加入群聊并成为群主，请等待成员同意入群"}')
        Logx(f'【CREATEROOM】Room#{roomnum}由{username}创建完成！')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【CREATEROOM】创建Room#{roomnum}时用户{username}账密验证不通过，创建失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、房间名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【CREATEROOM】Room#{roomnum}输入非法！')
    return result

@app.route('/addroom',methods=['POST'])
def addroom():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#","")
  intro = decrypt(data['introduction'])
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit():
    if username in userlist and userlist[username] == password :
      if "#"+roomnum not in chatroomlist or chatroomlist["#"+roomnum]=='':
          result=encrypt('{"result":"房间号不可用"}')
          Logx(f'【ADDROOM】Room#{roomnum}不存在，加入失败！')
          return result
      elif username in roommemberlist["#"+roomnum]:
          result=encrypt('{"result":"您已经在房间里了！"}')
          Logx(f'【ADDROOM】{username}已经在Room#{roomnum}，加入失败！')
          return result
      else:
        with write_lock:
          roomowner=roommemberlist["#"+roomnum][0]
          if roomowner not in addroomconfirm:
              addroomconfirm[roomowner] = {}
          if "#"+roomnum not in addroomconfirm[roomowner]:
              addroomconfirm[roomowner]["#" + roomnum] = []
          if username not in addroomconfirm[roomowner]["#" + roomnum]:
              addroomconfirm[roomowner]["#" + roomnum].append({username:intro})
          ARCSave()
        result = encrypt('{"result":"申请已发送，等待群主确认"}')
        Logx(f'【ADDROOM】{username}申请加入Room#{roomnum}，等待群主确认！')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【ADDROOM】加入Room#{roomnum}时用户{username}账密验证不通过，加入失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【ADDROOM】Room#{roomnum}输入非法！')
    return result

@app.route('/invitetoroom' ,methods = ["POST"])
def invitetoroom():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#","")
  intro = decrypt(data['introduction'])
  users = decrypt(data['users']).split(" ")
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit():
    if username in userlist and userlist[username] == password :
      if "#"+roomnum not in chatroomlist:
          result=encrypt('{"result":"房间号不存在"}')
          Logx(f'【invitetoroom】Room#{roomnum}不存在，邀请失败！')
          return result
      elif username not in roommemberlist["#"+roomnum]:
          result=encrypt('{"result":"您不在房间内！"}')
          Logx(f'【invitetoroom】{username}不在Room#{roomnum}，邀请失败！')
          return result
      else:
        with write_lock:
          for i in users:
            if i not in roommemberlist["#"+roomnum] and i in userlist:
              if i not in addroomconfirm:
                  addroomconfirm[i]={}
              if "群聊邀请" not in addroomconfirm[i]:
                  addroomconfirm[i]["群聊邀请"]=[]
              new_invite = {"#" + roomnum: f"(创建者:{namelist[username]}({username})){intro}"}
              if new_invite not in addroomconfirm[i]["群聊邀请"]:  # 检查是否已存在
                  addroomconfirm[i]["群聊邀请"].append(new_invite)
          ARCSave()
        rum(roomnum,f"**系统**：{namelist[username]}({username})邀请了{str(users)}进入Room#{roomnum}，请等待被邀请成员同意。若群主不同意入群，请进群后将其踢出。【{timenow}】")
        result=encrypt('{"result":"请等待成员同意入群"}')
        Logx(f'【invitetoroom】Room#{roomnum}由{username}邀请了一些人！')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【invitetoroom】创建Room#{roomnum}时用户{username}账密验证不通过，创建失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、房间名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【invitetoroom】Room#{roomnum}输入非法！')
    return result

@app.route('/getroomname',methods=['POST'])
def getroomname():
  data = request.get_json()
  roomnum = decrypt(data['roomnum'])
  #print(roomnum)
  global chatroomlist
  return encrypt(chatroomlist.get(roomnum,"【这个群聊不存在！】"))

@app.route('/getroommember',methods=['POST'])
def getroommember():
    data = request.get_json()
    roomnum = decrypt(data['roomnum'])
    username = decrypt(data['username'])
    password = toSHA256(decrypt(data['password']))
    global userlist,roommemberlist
    if not (v(username) and v(password) and roomnum.replace("#","").isdigit()):
        result=encrypt('{"result":"用户名、房间名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
        Logx(f'【getroommember】输入非法！')
        return result
    if username not in userlist or userlist[username] != password:
        result=encrypt('{"result":"账号验证失败"}')
        Logx(f'【getroommember】账号验证失败！')
        return result
    if roomnum not in roommemberlist or username not in roommemberlist[roomnum]:
        result=encrypt('{"result":"您不在群聊内！"}')
        Logx(f'【getroommember】不在群聊内！')
        return result
    with read_lock:
        ulist = roommemberlist[roomnum]
        udict={}
        for i in range(len(ulist)):
              udict[namelist[ulist[i]]]=ulist[i]
    d = jsondict({
        "members":json.dumps(udict),
        "is_owner":roommemberlist[roomnum][0]==username,
        "result":"success"})
    return encrypt(d)

@app.route('/changeroomname',methods=['POST'])
def changeroomname():
    data = request.get_json()
    roomnum = decrypt(data['roomnum'])
    username = decrypt(data['username'])
    password = toSHA256(decrypt(data['password']))
    newname = decrypt(data['newname'])
    #print("666here",roomnum,username,password,newname)
    timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    if not (v(username) and v(password) and roomnum.replace("#","").isdigit() and v(newname)):
        result=encrypt('{"result":"用户名、房间名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
        Logx(f'【changeroomname】输入非法！')
        return result
    elif username not in userlist or userlist[username] != password:
        result=encrypt('{"result":"账号验证失败"}')
        Logx(f'【changeroomname】账号验证失败！')
        return result
    elif roomnum not in roommemberlist or username not in roommemberlist[roomnum] or username != roommemberlist[roomnum][0]:
        result=encrypt('{"result":"您不在群聊内/不是群主，不能修改群名称！"}')
        Logx(f'【changeroomname】不在群聊内！')
        return result
    else:
        with write_lock:
            chatroomlist[roomnum]=newname
            ChatRoomListSave()
        rum(roomnum.replace("#",""),f"**系统**：{namelist[username]}({username})修改Room{roomnum}名称为{newname}【{timenow}】")
        result=encrypt('{"result":"修改名称完成！"}')
        Logx(f'【changeroomname】修改名称完成！')
        return result 

@app.route('/deleteroom',methods=['POST'])
def deleteroom():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#","")
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit() and roomnum != '1' and roomnum != '#1':
    if username in userlist and userlist[username] == password :
      if "#"+roomnum not in chatroomlist or chatroomlist["#"+roomnum]=='':
          result=encrypt('{"result":"房间号不可用"}')
          Logx(f'【DELETEROOM】Room#{roomnum}不存在，删除失败！')
          return result
      elif username != roommemberlist["#"+roomnum][0]:
          result=encrypt('{"result":"无权删除房间"}')
          Logx(f'【DELETEROOM】{username}不是Room#{roomnum}的群主，删除失败！')
          return result
      else:
        with write_lock:
          arc = '无'
          if username in addroomconfirm and "#"+roomnum in addroomconfirm[username]:#此时username=roomowner
              arc=addroomconfirm[username].pop("#"+roomnum,'无')
              if addroomconfirm[username]=={}:
                  addroomconfirm.pop(username)#删除没有请求的群主键值对
              ARCSave()
          for uname,ucl in userchatlist.items():
              if '#'+roomnum in ucl:
                  ucl.remove('#'+roomnum)
          UserChatListSave()
          with open("Data/deletedroom.txt", "a", encoding='utf-8') as file:
              file.write(jsondict({
                  'time':timenow,
                  'roomnum':'#'+roomnum,
                  'roomownner':username,
                  'roomname':chatroomlist.pop("#"+roomnum,'无'),
                  'members':roommemberlist.pop("#"+roomnum,'无'),
                  'WaitingUser(ARC)':arc}))
          ChatRoomListSave()
          RoomMemberListSave()
        try:
          with write_lock:
            old_name = "Message/Room#" + roomnum + ".txt"
            new_name = "Message/Room#" + roomnum + f"(backup{time.strftime('%Y%m%d %H%M%S', time.localtime())}).txt"
            os.rename(old_name, new_name)
            print(f"文件名已从 {old_name} 修改为 {new_name}")
        except FileNotFoundError:
            print(f"文件 {old_name} 不存在")
        except FileExistsError:
            print(f"文件 {new_name} 已存在")
        result = encrypt('{"result":"群聊已成功删除"}')
        Logx(f'【DELETEROOM】{username}删除Room#{roomnum}完成，群聊信息及聊天记录已保留。')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【DELETEROOM】删除Room#{roomnum}时用户{username}账密验证不通过，删除失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【DELETEROOM】Room#{roomnum}输入非法！')
    return result

@app.route('/addroomconfirm',methods=['POST'])
def ARCMethod():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#","")
  waitinguser = decrypt(data['waitinguser'])
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit() and v(waitinguser):
    if username in userlist and userlist[username] == password :
      if "#"+roomnum not in chatroomlist or chatroomlist["#"+roomnum]=='':
          result=encrypt('{"result":"房间号不可用"')
          Logx(f'【ADDROOMCONFIRM】Room#{roomnum}不存在，{waitinguser}加入确认失败！')
          return result
      elif username != roommemberlist["#"+roomnum][0]:
          result=encrypt('{"result":"无权确认加入"}')
          Logx(f'【ADDROOMCONFIRM】{username}不是Room#{roomnum}的群主，{waitinguser}加入确认失败！')
          return result
      elif waitinguser in roommemberlist["#"+roomnum]:
          result=encrypt('{"result":"'+waitinguser+'已经在房间里啦！"}')
          Logx(f'【ADDROOMCONFIRM】{waitinguser}已经在Room#{roomnum}，加入确认失败！')
          return result
      elif waitinguser not in userlist:
          result=encrypt('{"result":"账号验证不通过"}')
          Logx(f'【ADDROOMCONFIRM】{waitinguser}账号不存在，加入确认失败！')
          return result
      else:
        with write_lock:
          # 遍历该群聊下的所有请求
          for req in addroomconfirm[username]["#"+roomnum][:]:  # 使用[:]创建副本避免迭代时修改
                        if waitinguser in req:  # 找到目标用户的请求
                            addroomconfirm[username]["#"+roomnum].remove(req)
                            print(f"已移除{waitinguser}向#{roomnum}的请求")
                            break
          else:
                result=encrypt('{"result":"'+waitinguser+'没申请过加入该房间"}')
                Logx(f'【ADDROOMCONFIRM】{waitinguser}没申请过加入Room#{roomnum}，加入确认失败！')
                return result
        
          # 如果已无请求，可以删除空列表（可选）
          if not addroomconfirm[username]["#"+roomnum]:
                        del addroomconfirm[username]["#"+roomnum]
                        print(f"#{roomnum}已无加入请求，已移除空列表")
          ARCSave()
          roommemberlist["#"+roomnum].append(waitinguser)
          RoomMemberListSave()
          userchatlist[waitinguser].insert(0,"#"+roomnum)
          UserChatListSave()
        rum(roomnum,f"**系统**：{namelist[username]}({username})同意{namelist[waitinguser]}({waitinguser})进入Room#{roomnum}【{timenow}】")
        result = encrypt('{"result":"您已成功同意'+waitinguser+'进入Room#'+roomnum+'"}')
        Logx(f'【ADDROOMCONFIRM】{waitinguser}申请加入Room#{roomnum}，由{username}确认完成！')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【ADDROOMCONFIRM】确认{waitinguser}加入Room#{roomnum}时群主{username}账密验证不通过，{waitinguser}加入确认失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【ADDROOMCONFIRM】Room#{roomnum}输入非法！')
    return result

@app.route('/addroomrefuse',methods=['POST'])
def ARRMethod():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#","")
  waitinguser = decrypt(data['waitinguser'])
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit() and v(waitinguser):
    if username in userlist and userlist[username] == password :
      with write_lock:
          # 遍历该群聊下的所有请求
          for req in addroomconfirm[username]["#"+roomnum][:]:  # 使用[:]创建副本避免迭代时修改
                        if waitinguser in req:  # 找到目标用户的请求
                            addroomconfirm[username]["#"+roomnum].remove(req)
                            print(f"已移除{waitinguser}向#{roomnum}的请求")
                            break
          else:
                        print(f"未找到{waitinguser}向#{roomnum}请求")
        
          # 如果已无请求，可以删除空列表（可选）
          if not addroomconfirm[username]["#"+roomnum]:
                        del addroomconfirm[username]["#"+roomnum]
                        print(f"#{roomnum}已无加入请求，已移除空列表")
          ARCSave()
      rum(roomnum,f"**系统**：{namelist[username]}({username})拒绝{namelist[waitinguser]}({waitinguser})进入Room#{roomnum}【{timenow}】")
      result = encrypt('{"result":"您已成功拒绝'+waitinguser+'进入Room#'+roomnum+'"}')
      Logx(f'【addroomrefuse】{waitinguser}申请加入Room#{roomnum}，由{username}拒绝完成！')
      return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【addroomrefuse】拒绝{waitinguser}加入Room#{roomnum}时群主{username}账密验证不通过，失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【addroomrefuse】Room#{roomnum}输入非法！')
    return result

@app.route('/quitroom',methods=['POST'])
def quitroom():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#","")
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit():
    if username in userlist and userlist[username] == password :
      if "#"+roomnum not in chatroomlist :
          result=encrypt('{"result":"房间号不可用"}')
          Logx(f'【QUITROOM】Room#{roomnum}不存在，{username}退出失败！')
          return result
      elif username not in roommemberlist["#"+roomnum]:
        if '#'+roomnum in userchatlist[username]:
            userchatlist[username].remove('#'+roomnum)
            UserChatListSave()
            result=encrypt('{"result":"退出成功"}')
            Logx(f'【QUITROOM】{username}退出僵尸群聊（已被踢过）Room#{roomnum}，退出成功！')
            return result
        else:
          result=encrypt('{"result":"您不在该房间！"}')
          Logx(f'【QUITROOM】{username}不在Room#{roomnum}，退出失败！')
          return result
      else:
        with write_lock:
          rr='您已退出该群'
          if roommemberlist['#'+roomnum][0]==username:
              rr='您是该房间的群主，您已退出该群，群主已自动转让给'+roommemberlist['#'+roomnum][1]
          userchatlist[username].remove('#'+roomnum)
          roommemberlist['#'+roomnum].remove(username)
          UserChatListSave()
          RoomMemberListSave()
        rum(roomnum,f"**系统**：{namelist[username]}({username}){rr.replace('您','')}【{timenow}】")
        result = encrypt('{"result":"'+rr+'"}')
        Logx(f'【QUITROOM】{username}{rr}')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【QUITROOM】退出Room#{roomnum}时用户{username}账密验证不通过，退出失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【QUITROOM】Room#{roomnum}输入非法！')
    return result

@app.route('/changeowner',methods=['POST'])
def changeowner():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#","")
  newowner = decrypt(data['newowner'])
  #print(username,password,roomnum,newowner)
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit() and v(newowner) and roomnum != '1' and roomnum != '#1':
    if username in userlist and userlist[username] == password :
      if "#"+roomnum not in chatroomlist or chatroomlist["#"+roomnum]=='':
          result=encrypt('{"result":"房间号不可用"}')
          Logx(f'【CHANGEOWNER】Room#{roomnum}不存在，{newowner}变成群主失败！')
          return result
      elif username != roommemberlist["#"+roomnum][0]:
          result=encrypt('{"result":"无权更改群主"}')
          Logx(f'【CHANGEOWNER】{username}不是Room#{roomnum}的群主，{newowner}变成群主失败！')
          return result
      elif newowner not in roommemberlist["#"+roomnum]:
          result=encrypt('{"result":"'+newowner+'不在房间内！"}')
          Logx(f'【CHANGEOWNER】{newowner}不在Room#{roomnum}，变成群主失败！')
          return result
      elif newowner not in userlist:
          result=encrypt('{"result":"账号验证不通过"}')
          Logx(f'【CHANGEOWNER】{newowner}账号不存在，变成群主失败！')
          return result
      else:
        with write_lock:
          roommemberlist["#"+roomnum].remove(newowner)
          roommemberlist["#"+roomnum].insert(0,newowner)
          RoomMemberListSave()
        rum(roomnum,f"**系统**：{namelist[username]}({username})在Room#{roomnum}的群主权限转给了{namelist[newowner]}({newowner})【{timenow}】")
        result = encrypt('{"result":"转让群主成功！"}')
        Logx(f'【CHANGEOWNER】{username}在Room#{roomnum}的群主权限转给了{newowner}，操作完成！')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【CHANGEOWNER】{newowner}成为Room#{roomnum}的群主时，原群主{username}账密验证不通过，失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【CHANGEOWNER】Room#{roomnum}输入非法！')
    return result

@app.route('/kickfromroom',methods=['POST'])
def kickfromroom():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#","")
  waitinguser = decrypt(data['waitinguser'])
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  #print(username,password,roomnum,waitinguser)
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit() and v(waitinguser):
    if username in userlist and userlist[username] == password :
      if "#"+roomnum not in chatroomlist or chatroomlist["#"+roomnum]=='':
          result=encrypt('{"result":"房间号不可用"}')
          Logx(f'【kickfromroom】Room#{roomnum}不存在，{waitinguser}踢出房间失败！')
          return result
      elif username != roommemberlist["#"+roomnum][0]:
          result=encrypt('{"result":"无权踢出"}')
          Logx(f'【kickfromroom】{username}不是Room#{roomnum}的群主，{waitinguser}踢出房间失败！')
          return result
      elif waitinguser not in roommemberlist["#"+roomnum]:
          result=encrypt('{"result":"'+waitinguser+'不在房间里！"}')
          Logx(f'【kickfromroom】{waitinguser}不在Room#{roomnum}，踢出房间失败！')
          return result
      elif waitinguser not in userlist:
          result=encrypt('{"result":"账号验证不通过"}')
          Logx(f'【kickfromroom】{waitinguser}账号不存在，踢出房间失败！')
          return result
      elif waitinguser == username:
          result=encrypt('{"result":"群主不能自己踢自己，请使用退出房间功能。"}')
          Logx(f'【kickfromroom】{waitinguser}群主不能自己踢自己，请使用退出房间功能。')
          return result
      else:
        with write_lock:
          #userchatlist[waitinguser].remove('#'+roomnum)  #不删除用户聊天列表，但是用户无法收发消息
          roommemberlist['#'+roomnum].remove(waitinguser)
          #UserChatListSave()
          RoomMemberListSave()
        rum(roomnum,f"**系统**：{namelist[username]}({username})把{namelist[waitinguser]}({waitinguser})踢出Room#{roomnum}完成【{timenow}】")
        result = encrypt('{"result":"踢出成员成功"}')
        Logx(f'【kickfromroom】{username}把{waitinguser}踢出Room#{roomnum}完成。')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【kickfromroom】把{waitinguser}踢出Room#{roomnum}时群主{username}账密验证不通过，{waitinguser}踢出失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【kickfromroom】Room#{roomnum}输入非法！')
    return result


#私聊
@app.route('/adduser', methods=['POST'])
def adduser():
    data = request.get_json()
    username = decrypt(data['username'])
    password = toSHA256(decrypt(data['password']))
    friendUsername = decrypt(data['friendUsername'])  # 修复参数名
    intro = decrypt(data['introduction'])
    #print(username,password,friendUsername)
    global userlist, namelist, addroomconfirm
    timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    Logx(f"【ADDUSER】收到好友请求: {username} -> {friendUsername}")
    if v(username) and v(password) and v(friendUsername):
        if (username in userlist and 
            userlist[username] == password and 
            friendUsername in userlist):
            if username == friendUsername:
                result = encrypt('{"result":"添加失败！不能添加自己为好友！"}')
                Logx(f'【ADDUSER】{username}申请添加自己，不行！！！')
                return result
            with write_lock:
                if friendUsername not in addroomconfirm:
                    addroomconfirm[friendUsername] = {}
                if '好友' not in addroomconfirm[friendUsername]:
                    addroomconfirm[friendUsername]['好友'] = []
                # 避免重复添加请求
                if username not in addroomconfirm[friendUsername]['好友']:
                    addroomconfirm[friendUsername]['好友'].append({username:intro})
                    ARCSave()
                    result = encrypt('{"result":"申请已发送，等待对方确认"}')
                    Logx(f'【ADDUSER】{username}申请添加{friendUsername}，等待对方确认！')
                else:
                    result = encrypt('{"result":"您已发送过好友请求，请等待对方确认"}')
                    Logx(f'【ADDUSER】{username}已发送过给{friendUsername}的好友请求')
            return result
        else:
            result = encrypt('{"result":"添加失败！账号验证不通过"}')
            Logx(f'【ADDUSER】{username}添加{friendUsername}时账密验证不通过')
            return result
    else:
        result = encrypt('{"result":"添加失败！用户名、密码和好友用户名只允许中文、数字、字母"}')
        Logx(f'【ADDUSER】输入非法！username={username}, friendUsername={friendUsername}')
        return result

@app.route('/adduserconfirm',methods=['POST'])#username同意添加user
def adduserconfirm():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  user = decrypt(data['user'])
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and v(user):
    if username in userlist and userlist[username] == password and user in userlist:
        if username not in addroomconfirm or '好友' not in addroomconfirm[username]:
            result=encrypt('{"result":"对方未申请过加您为好友"}')
            Logx(f'【ADDUSERCONFIRM】{user}压根不想加{username}为好友，别自作多情！加好友确认失败！')
            return result
        else:
          with write_lock:
                    # 遍历该群聊下的所有请求
                    for req in addroomconfirm[username]["好友"][:]:  # 使用[:]创建副本避免迭代时修改
                        if user in req:  # 找到目标用户的请求
                            addroomconfirm[username]["好友"].remove(req)
                            print(f"已移除{user}向{username}的请求")
                            break
                    else:
                         result=encrypt('{"result":"对方未申请过加您为好友"}')
                         Logx(f'【ADDUSERCONFIRM】{user}压根不想加{username}为好友，别自作多情！加好友确认失败！')
                         return result
        
                    # 如果已无请求，可以删除空列表（可选）
                    if not addroomconfirm[username]["好友"]:
                        del addroomconfirm[username]["好友"]
                        print(f"{username}已无好友请求，已移除空列表")
                    ARCSave()
          while True:
              rn = random.randint(2,100000)
              if '#'+str(rn) not in chatroomlist:
                  with write_lock:
                      roommemberlist['#'+str(rn)] = [username,user]
                      RoomMemberListSave()
                      userchatlist[user].append('#'+str(rn))
                      userchatlist[username].append('#'+str(rn))
                      UserChatListSave()
                      chatroomlist['#'+str(rn)] = namelist[username]+'和'+namelist[user]
                      ChatRoomListSave()
                  break
        result = encrypt('{"result":"您已成功添加'+user+'，开始聊天吧！私聊群号Room#'+str(rn)+'"}')
        Logx(f'【ADDUSERCONFIRM】{username}同意添加{user}，私聊群号Room#{str(rn)}')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【ADDUSERCONFIRM】{username}同意添加{user}时账密验证不通过，失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【ADDUSERCONFIRM】输入非法！')
    return result

@app.route('/adduserrefuse',methods=['POST'])#username拒绝添加user
def adduserrefuse():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  user = decrypt(data['user'])
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and v(user):
    if username in userlist and userlist[username] == password :
        if username not in addroomconfirm or '好友' not in addroomconfirm[username]:
            result=encrypt('{"result":"对方未申请过加您为好友"}')
            Logx(f'【ADDUSERREFUSE】{user}压根不想加{username}为好友，别自作多情！加好友确认失败！1')
            return result
        else:
          with write_lock:
                    # 遍历该群聊下的所有请求
                    for req in addroomconfirm[username]["好友"][:]:  # 使用[:]创建副本避免迭代时修改
                        if user in req:  # 找到目标用户的请求
                            print(req)
                            addroomconfirm[username]["好友"].remove(req)
                            print(f"已移除{user}向{username}的请求")
                            break
                    else:
                         result=encrypt('{"result":"对方未申请过加您为好友"}')
                         Logx(f'【ADDUSERCONFIRM】{user}压根不想加{username}为好友，别自作多情！加好友确认失败！2')
                         return result
        
                    # 如果已无请求，可以删除空列表（可选）
                    if not addroomconfirm[username]["好友"]:
                        del addroomconfirm[username]["好友"]
                        print(f"{username}已无好友请求，已移除空列表")
                    ARCSave()
        result = encrypt('{"result":"您已成功拒绝对方！"}')
        Logx(f'【ADDUSERREFUSE】{username}拒绝添加{user}完成！')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【ADDUSERREFUSE】{username}拒绝添加{user}时账密验证不通过，失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【ADDUSERREFUSE】输入非法！')
    return result

#新增：同意/拒绝群聊邀请
@app.route('/roominvite',methods=['POST'])#username添加群聊roomnum
def roominvite():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum'])
  action = decrypt(data['action'])
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and (action=="agree" or action=="deny") and roomnum.replace("#","").isdigit():
    if username in userlist and userlist[username] == password:
        if username not in addroomconfirm or '群聊邀请' not in addroomconfirm[username] or roomnum not in chatroomlist:
            result=encrypt('{"result":"您未被邀请过加入此群！"}')
            Logx(f'【roominvite】{username}未被邀请过加入Room{roomnum}')
            return result
        else:
          with write_lock:
                    for req in addroomconfirm[username]["群聊邀请"][:]:  # 使用[:]创建副本避免迭代时修改
                        if roomnum in req:  # 找到目标用户的请求
                            addroomconfirm[username]["群聊邀请"].remove(req)
                            print(f"已移除{roomnum}向{username}的邀请")
                            break
                    else:
                        result=encrypt('{"result":"您未被邀请过加入此群！"}')
                        Logx(f'【roominvite】{username}未被邀请过加入Room{roomnum}')
                        return result
        
                    # 如果该群聊已无请求，可以删除空列表（可选）
                    if not addroomconfirm[username]["群聊邀请"]:
                        del addroomconfirm[username]["群聊邀请"]
                        print(f"{username}已无群聊邀请，已移除空列表")
                    ARCSave()
                    result = encrypt('{"result":"您已成功拒绝邀请。"}')
                    if action=="agree":
                        roommemberlist[roomnum].append(username)
                        RoomMemberListSave()
                        userchatlist[username].append(roomnum)
                        UserChatListSave()
                        result = encrypt('{"result":"您已成功加入群聊！"}')
        if action=="agree":
            rum(roomnum.replace("#",""),f"**系统**：{namelist[username]}({username})同意加入Room{roomnum}【{timenow}】")
        else:
            rum(roomnum.replace("#",""),f"**系统**：{namelist[username]}({username})拒绝加入Room{roomnum}【{timenow}】")
        Logx(f'【roominvite】{username}加入/拒绝Room{roomnum}完成！')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【roominvite】{username}处理{roomnum}邀请时账密验证不通过，失败！')
        return result
  else:
    result=encrypt('{"result":"用户名、密码只允许中文、数字、字母（中文密码也行），房间号只允许整数数字"}')
    Logx(f'【roominvite】输入非法！')
    return result


#消息管理
@app.route('/sendmessage',methods=['POST'])#message是用户要发的消息，更新：完整内容！！！！以前只包括内容，不包括用户名和时间
def sendmessage():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#", "")
  message = decrypt(data['message'])
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit() and "【**RECALL**】》" not in message:
    if username in userlist and userlist[username] == password :
      if "#"+roomnum not in chatroomlist or chatroomlist["#"+roomnum]=='':
          result=encrypt('{"result":"房间号不可用"}')
          Logx(f'【sendmessage】Room#{roomnum}不存在，{username}发送消息{message}失败！')
          return result
      elif username not in roommemberlist["#"+roomnum]:
          result=encrypt('{"result":"您不在房间里，不能发消息！"}')
          Logx(f'【sendmessage】{username}不在Room#{roomnum}，发消息失败！')
          return result
      else:
        rum(roomnum,message)
        result = encrypt('{"result":"success"}')
        Logx(f'【sendmessage】{username}在Room#{roomnum}发送了{message}，消息已存储。')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【sendmessage】{username}账号验证不通过')
        return result
  else:
    result=encrypt('{"result":"消息不能包括“【**RECALL**】》”字样（就这一个要求，忍忍哈）"}')
    Logx(f'【sendmessage】输入非法！')
    return result

@app.route('/getmessage',methods=['POST'])
#此处的message是客户端已接收的最后一条消息，如果服务器没保存过这条消息就直接返回所有，否则返回这条消息后的消息（没有就是空字符串）。需要注意message包括内容、用户名和时间
def getmessage():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#", "")
  message = decrypt(data['message'])
  print('!!!!!!!!!!getmessage：',username,password,roomnum,message)
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit() and "【**RECALL**】》" not in message:
    if username in userlist and userlist[username] == password :
      if "#"+roomnum not in chatroomlist or chatroomlist["#"+roomnum]=='':
          result=encrypt(f'错误：房间号不可用【{timenow}】')
          Logx(f'【getmessage】Room#{roomnum}不存在，{username}接收消息失败！')
          return result
      elif username not in roommemberlist["#"+roomnum]:
          result=encrypt(f'错误：请先加入房间，再收消息！【{timenow}】')
          Logx(f'【getmessage】{username}不在Room#{roomnum}，收消息失败！')
          return result
      else:
        result = encrypt(lat(roomnum,message))
        Logx(f'【getmessage】{username}接收Room#{roomnum}的消息完成')
        return result
    else:
        result=encrypt(f'错误：账号验证不通过【{timenow}】')
        Logx(f'【getmessage】{username}账号验证不通过')
        return result
  else:
    result=encrypt(f'错误：消息不能包括“【**RECALL**】》”字样（就这一个要求，忍忍哈）【{timenow}】')
    Logx(f'【getmessage】输入非法！')
    return result

@app.route('/revokemessage',methods=['POST'])#message是用户要撤的消息，包括内容，用户名和时间
def revokemessage():
  data = request.get_json()
  username = decrypt(data['username'])
  password = toSHA256(decrypt(data['password']))
  roomnum = decrypt(data['roomnum']).replace("#", "")
  message = decrypt(data['message'])
  #print(data)
  #print(username,password,roomnum,message)
  global userlist, namelist,userchatlist,chatroomlist,roommemberlist
  timenow = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
  if v(username) and v(password) and roomnum.isdigit() and "【**RECALL**】》" not in message:
    if username in userlist and userlist[username] == password :
      if "#"+roomnum not in chatroomlist or chatroomlist["#"+roomnum]=='':
          result=encrypt('{"result":"房间号不可用"}')
          Logx(f'【revokemessage】Room#{roomnum}不存在，{username}撤回消息{message}失败！')
          return result
      elif username not in roommemberlist["#"+roomnum]:
          result=encrypt('{"result":"您不在房间里，不能撤回消息！"}')
          Logx(f'【revokemessage】{username}不在Room#{roomnum}，撤回消息失败！')
          return result
      elif message not in lat(roomnum,'all'):
          result=encrypt('{"result":"这个消息不存在"}')
          Logx(f'【revokemessage】{message}不在Room#{roomnum}聊天记录中，{username}撤回消息失败！')
          return result
      elif not i30(message):
          result=encrypt('{"result":"只能撤回30分钟内的消息"}')
          Logx(f'【revokemessage】{message}超过半小时，{username}撤回消息失败！')
          return result
      elif message.split("：", 1)[0]!=username:
          result=encrypt('{"result":"您不能撤回别人的消息！"}')
          Logx(f'【revokemessage】{username}尝试撤回别人的{message}，撤回消息失败！')
          return result
      elif "【**RECALL**】》"+message+"《【**RECALL**】" in lat(roomnum,'all'):
          result=encrypt('{"result":"您不能重复撤回消息！"}')
          Logx(f'【revokemessage】{username}尝试重复撤回{message}，撤回消息失败！')
          return result
      else:
        rum(roomnum,"【**RECALL**】》"+message+"《【**RECALL**】")
        result = encrypt('{"result":"success"}')
        Logx(f'【revokemessage】{username}撤回在Room#{roomnum}发送的{message}，需求已存储。')
        return result
    else:
        result=encrypt('{"result":"账号验证不通过"}')
        Logx(f'【revokemessage】{username}账号验证不通过')
        return result
  else:
    result=encrypt('{"result":"消息不能包括“【**RECALL**】》”字样（就这一个要求，忍忍哈）"}')
    Logx(f'【revokemessage】输入非法！')
    return result


############评价系统 来自增稠剂#############
def save_issue(username, rating, comment):
    """保存评价到文件"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ISSUE_FILE, "a", encoding="utf-8") as f:
        f.write(f"{timestamp}|{username}|{rating}|{comment}"+os.linesep)

def get_recent_issues():
    """获取最近3条评价"""
    try:
        with open(ISSUE_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            # 取最后3条并反转顺序（最新的在前）
            recent_lines = lines[-3:][::-1]
            issues = []
            for line in recent_lines:
                parts = line.strip().split("|", 3)
                if len(parts) >= 4:
                    issues.append({
                        "time": parts[0],
                        "user": namelist.get(parts[1],"未知用户"),
                        "rating": int(parts[2]),
                        "comment": parts[3]
                    })
            return issues
    except Exception as e:
        print(f"读取文件错误: {e}")
        return []

def has_user_commented(username):
    """检查用户是否已经评价过"""
    try:
        with open(ISSUE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split("|", 3)  # 分割成4部分
                if len(parts) >= 4 and parts[1] == username:
                    return True
    except FileNotFoundError:
        return False
    return False

@app.route('/submitissue', methods=['POST'])
def submit_issue():
    global userlist
    """提交评价API"""
    try:
        data = request.json
        if not data:
            return encrypt('{"status": "error", "message": "无效的请求数据"}')

        # 解密所有字段
        try:
            rating = decrypt(data.get('rating', ''))
            comment = decrypt(data.get('comment', ''))
            username = decrypt(data.get('username', ''))
            password = toSHA256(decrypt(data.get('password', '')))
        except Exception as decrypt_error:
            print(f"解密失败: {decrypt_error}")
            return encrypt('{"status": "error", "message": "数据解密失败，请刷新页面"}')

        # 检查解密后的数据有效性
        if '错误' in username or '错误' in password:
            return encrypt('{"status": "error", "message": "会话密钥已过期，请刷新网页！"}')

        # 验证用户凭证
        if username not in userlist or userlist[username] != password:
            return encrypt('{"status": "error", "message": "账号验证失败"}')
        '''
        # 检查是否已评价
        if has_user_commented(username):
            return encrypt('{"status": "error", "message": "您已经评价过了！"}')
        '''
        # 验证评分
        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                return encrypt('{"status": "error", "message": "评分必须在1-5之间"}')
        except (ValueError, TypeError):
            return encrypt('{"status": "error", "message": "无效的评分格式"}')

        # 保存评价
        save_issue(username, rating, comment)
        return encrypt('{"status": "success"}')

    except Exception as e:
        print(f"服务器内部错误: {str(e)}")
        return encrypt('{"status": "error", "message": "服务器处理请求时出错"}')

@app.route('/getissue', methods=['GET'])
def get_issue():
    """获取最近评价API"""
    try:
        issues = get_recent_issues()
        # 确保issues是字典列表格式
        if not isinstance(issues, list):
            issues = []
        return encrypt(json.dumps(issues))
    except Exception as e:
        print(f"获取评价错误: {str(e)}")
        return encrypt(json.dumps([]))  # 返回空数组而不是报错


#########################################公告#################################################
# 默认配置
current_config = {
    "noticeboard": "默认公告",
    "url": "NONE"
}

def load_config():
    global current_config
    config_file = "Data/lanmeichat.ntc"
    
    try:
        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = json.loads(f)
                
            # 更新配置
            if "noticeboard" in config_data:
                notice_data = config_data["noticeboard"]
                current_config = {
                    "noticeboard": notice_data.get("notice", "默认公告"),
                    "url": notice_data.get("url", "NONE")
                }
                print(f"配置已更新: {current_config}")
        else:
            print(f"配置文件 {config_file} 不存在，使用默认配置")
            
    except Exception as e:
        print(f"加载配置文件时出错: {e}")

def config_loader_loop():
    """每10分钟加载一次配置文件的循环"""
    while True:
        load_data()
        print("子线程loaddata")
        time.sleep(300)  # 5分钟

@app.route('/noticeboard', methods=['GET'])
def get_noticeboard():
    return jsonify(current_config)
    
application = app

if __name__ == '__main__':
    # 初始加载配置
    load_config()
    
    # 启动后台线程定期加载配置
    loader_thread = Thread(target=config_loader_loop, daemon=True)
    loader_thread.start()

    app.run(host='0.0.0.0', port=7789, debug=False)

