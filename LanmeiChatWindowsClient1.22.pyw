import sys,os,requests,ast,time,json,hashlib
from PyQt5.QtWidgets import QProgressDialog,QFileDialog,QDialog,QInputDialog,QFrame,QMenu, QAction,QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLabel, QHBoxLayout, QLineEdit, QMessageBox,QLayout,QScrollArea,QSizePolicy,QListView,QAbstractItemView, QStyledItemDelegate, QStyle,QTextEdit
from PyQt5.QtCore import Qt,QRect,QPropertyAnimation,QSize, QAbstractListModel, QModelIndex,QTimer,pyqtSignal
from PyQt5.QtGui import QPixmap,QPainter,QPainterPath,QFont, QColor, QPen, QClipboard
from qt_material import apply_stylesheet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64,socket,shutil,webbrowser,threading,sys,re
from binascii import Error as Base64Error
import qtawesome as qta
from ftplib import FTP,error_perm
from pathlib import Path

#配置表，您需要修改
version=" V1.2" #版本号
server="https://example.lanmei.chat/" #服务器地址，需要https://或http://，末尾必须加/，IP也可以
short_server="example.lanmei.chat" #简短的服务器地址，不要上述东西
server_port=443 #https就填443，http就填80，IP就填端口
ftp_server="ftp-example.lanmei.chat" #不需要ftp://
ftp_port=8021
ftp_username="ftpuser"
ftp_password="ftppwd"
skey=bytes.fromhex("0123456789abcdef0123456789abcdef") #32位16进制字符串，应与服务端key.txt第一行保持一致
siv=bytes.fromhex("0123456789abcdef") #16位16进制字符串，应与服务端key.txt第二行保持一致

#请遵守开源协定。您在本客户端不得抹除以下内容：
#1.我们的官方官网lanmei.chat，不过您可以自建官网并添加在您的客户端
#2.我们的原开发者名字
#3.如果修改软件名称，必须在关于页面标注蓝莓通讯是原名称
#感谢您选择蓝莓通讯，其他请便，用的愉快！


def extract_first_url(text):
    # 正则表达式匹配http或https开头的URL，遇到中文、空格或非法字符时停止
    pattern = r'https?://[^\s<>"\'()\u4e00-\u9fff]+'
    match = re.search(pattern, text)
    return match.group(0) if match else None

def resource_path(relative_path):
    """ 获取资源的绝对路径，适用于开发环境和 PyInstaller 打包后的环境 """
    try:
        # PyInstaller 创建的临时文件夹路径
        base_path = sys._MEIPASS
    except Exception:
        # 正常开发环境下的路径
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


tmpapp = QApplication(sys.argv)
try:
    with socket.create_connection((short_server,server_port), timeout=10):
        print('连接成功')
except (ConnectionRefusedError, socket.timeout):
  '''
  try:
    with open("key.txt", "r", encoding='utf-8') as file:
        lines=file.readlines()
        skey=bytes.fromhex(lines[0].strip())
        siv=bytes.fromhex(lines[1].strip())
  except FileNotFoundError:
      QMessageBox.critical(None, 'Lanmei Chat - 错误',f"（key错误）第一次使用请先联网并登录")
      tmpapp.exec_()
      os._exit(1)
  except Exception as e:
      QMessageBox.critical(None, 'Lanmei Chat - 错误',f"（key错误）{str(e)}")
      tmpapp.exec_()
      os._exit(1)
      '''
  QMessageBox.critical(None, 'Lanmei Chat - 错误', '无法连接到服务器，请联系开发者！')
  tmpapp.exec_()  # 等待用户关闭消息框
  os._exit(1)

# 服务器
def r(r):
    try:
        response = requests.get(server+r, timeout=10)
        response.raise_for_status()  # 检查HTTP错误
        return response.text
    except requests.exceptions.Timeout:
        QMessageBox.critical(None, 'Lanmei Chat - 错误',f'{r}请求超时，无法连接到服务器！')
        tmpapp.exec_()
    except requests.exceptions.RequestException as e:
        QMessageBox.critical(None, 'Lanmei Chat - 错误', e)
        tmpapp.exec_()

def p(p,data):
    try:
        response = requests.post(server+p,json=data, timeout=10)
        response.raise_for_status()  # 检查HTTP错误
        return response.text
    except requests.exceptions.Timeout:
        QMessageBox.critical(None, 'Lanmei Chat - 错误', f'{p}请求超时，无法连接到服务器！')
        tmpapp.exec_()
    except requests.exceptions.RequestException as e:
        QMessageBox.critical(None, 'Lanmei Chat - 错误', e)
        tmpapp.exec_()

# AES
kai=ast.literal_eval(r('hello'))
'''
s = ast.literal_eval(r('key'))
print(s)
with open("key.txt", "w", encoding='utf-8') as file:
        file.write(s[0]+os.linesep+s[1])
skey=bytes.fromhex(s[0])
siv=bytes.fromhex(s[1])
'''

def sencrypt(data: str) -> str:
    cipher = AES.new(skey, AES.MODE_CBC, siv)
    encrypted = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(encrypted).decode('utf-8')

def sdecrypt(encrypted_data: str) -> str:
    """解密数据，自动处理可能的错误"""
    try:
        # 1. Base64 解码
        encrypted_bytes = base64.b64decode(encrypted_data)
        # 2. AES 解密
        cipher = AES.new(skey, AES.MODE_CBC, siv)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        # 3. 去除填充
        plaintext = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
        return plaintext
    except Base64Error:
        #QMessageBox.critical(None, 'Lanmei Chat - 错误', "s（错误）无效的 Base64 编码")
        return "s（错误）无效的 Base64 编码"
    except ValueError as e:
        if "Padding is incorrect." in str(e):
            QMessageBox.critical(None, 'Lanmei Chat - 错误', "s（错误）会话密钥已过期，请重启客户端！")
            return "s（错误）会话密钥已过期，请重启客户端！"
        else:
            #QMessageBox.critical(None, 'Lanmei Chat - 错误', f"s（错误）{str(e)}")
            return f"s（错误）{str(e)}"
    except Exception as e:
            #QMessageBox.critical(None, 'Lanmei Chat - 错误', f"s（错误：解密失败）{str(e)}")
            return f"s（错误：解密失败）{str(e)}"

KEY = bytes.fromhex(sdecrypt(kai[0]))
IV = bytes.fromhex(sdecrypt(kai[1]))
print(sdecrypt(kai[0]),sdecrypt(kai[1]))
#print(KEY,IV)

def encrypt(data: str) -> str:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
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
        #QMessageBox.critical(None, 'Lanmei Chat - 错误', "（错误）无效的 Base64 编码")
        return "（错误）无效的 Base64 编码"
    except ValueError as e:
        if "Padding is incorrect." in str(e):
            QMessageBox.critical(None, 'Lanmei Chat - 错误', "（错误）会话密钥已过期，请重启客户端！")
            return "（错误）会话密钥已过期，请重启客户端！"
        else:
            #QMessageBox.critical(None, 'Lanmei Chat - 错误', f"（错误）{str(e)}")
            return  f"（错误）{str(e)}"
    except Exception as e:
            #QMessageBox.critical(None, 'Lanmei Chat - 错误', f"（错误：解密失败）{str(e)}")
            return  f"（错误：解密失败）{str(e)}"

#namelist
namelist = ast.literal_eval(decrypt(r("name")))

#CONFIG
config={}
username=''
password=''
rid=''
is_owner=False
try:
    with open("config.txt", "r", encoding='utf-8') as file:
        config = json.load(file)
        if 'username' in config and 'password' in config:
            username = sdecrypt(config["username"])
            password = sdecrypt(config["password"])
except FileNotFoundError:
    pass
except Exception as e:
    QMessageBox.critical(None, 'Lanmei Chat - 错误',f"（config错误）{str(e)}")
    tmpapp.exec_()
    os._exit(1)

def configsave():
    with open("config.txt", "w", encoding='utf-8') as file:
        json.dump(config, file, ensure_ascii=False, indent=2)

def extract_core_content(msg):
    """
    提取消息核心内容，正确处理包含【】的消息和时间戳
    输入格式：发送人：消息内容【时间】
    返回：消息内容（不包含发送人和时间戳）
    """
    try:
        # 1. 先分离时间戳（总是最后的【】内容）
        if "【" in msg and "】" in msg:
            # 从右侧找到最后一个【和】
            last_left = msg.rfind("【")
            last_right = msg.rfind("】")
            
            if last_left < last_right:  # 确保是有效的【】对
                msg = msg[:last_left]  # 移除时间戳部分
        
        # 2. 移除发送者名称（第一个：之前的内容）
        if "：" in msg:
            msg = msg.split("：", 1)[1]  # 只分割第一个冒号
        
        # 3. 清理空白和特殊字符
        return msg.strip().replace("\u200B", "")
    
    except Exception as e:
        print(f"提取消息内容出错: {e}")
        return msg  # 出错时返回原始消息


# message
def get_last_line(rn):  # without#
    try:
        with open(f"Message {username}/Room" + rn + ".txt", 'rb') as f:  # 二进制模式读取
            content = f.read()
            if not content:  # 空文件
                return 'all'
            
            # 统一换行符为 \n 便于处理（兼容 \r\n 和 \r）
            content = content.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
            
            # 分割所有行
            lines = content.split(b'\n')
            
            # 从最后一行开始反向查找
            for line in reversed(lines):
                line_str = line.decode('utf-8').strip()
                if "【已撤回的内容】" not in line_str and line_str:  # 找到不包含该文本的非空行
                    return line_str
            
            # 如果所有行都包含"【已撤回的内容】"或为空
            return 'all'
                
    except FileNotFoundError:
        return 'all'
    except Exception as e:
        print(f"获取最后一行错误: {e}")
        return 'all'
    
def save_message(rn, message):
    filename = f"Message {username}/Room{rn}.txt"
    # 移除消息内容中现有的换行符
    message = message.strip('\n\r')  # 关键修改
    
    file_exists = os.path.exists(filename)
    file_empty = not file_exists or os.stat(filename).st_size == 0
    
    with open(filename, 'a', encoding='utf-8') as f:
        if file_empty:
            f.write(message)
        else:
            f.write(os.linesep + message)  # 统一由这里控制换行

def get_local_message(rn):
    try:
        with open(f"Message {username}/Room" + rn + ".txt", 'r', encoding='utf-8') as f:
            return f.read()
    except  FileNotFoundError: 
            return ''


#组件
class ChatBubble(QWidget):
    reply_requested = pyqtSignal(str) 
    def __init__(self, sender, text, time, is_left=True, parent=None):
        super().__init__(parent)
        self.is_left = is_left
        self.sender = sender
        self.text = text
        self.time = time
        self.setup_ui()
        self.setContextMenuPolicy(Qt.CustomContextMenu)  # 启用右键菜单
        self.customContextMenuRequested.connect(self.show_context_menu)
        
    def setup_ui(self):
        try:
            self.setMinimumHeight(70)
            
            # 获取屏幕DPI缩放比例
            screen = QApplication.primaryScreen()
            dpi_scale = screen.logicalDotsPerInch() / 96.0
            base_font_size = 15
            
            layout = QVBoxLayout()
            layout.setContentsMargins(10, 5, 10, 5)
            layout.setSpacing(2)
            
            # 设置字体大小根据DPI缩放
            self.setStyleSheet(f"font-size: {base_font_size * dpi_scale}px;")
        
            self.sender_label = QLabel(self.sender)
            self.sender_label.setStyleSheet("font-weight: bold; font-size: 15px;")
            if self.is_left:
                self.sender_label.setAlignment(Qt.AlignLeft)
            else:
                self.sender_label.setAlignment(Qt.AlignRight)

            formatted_text = self.text.replace("", "\u200B")[1:-1]
            self.message_label = QLabel(formatted_text)
            self.message_label.setWordWrap(True)
            self.message_label.setCursor(Qt.PointingHandCursor if "【文件】" in self.text else Qt.ArrowCursor)
            self.message_label.mousePressEvent = self.handle_message_click  # 添加点击事件
        
            self.time_label = QLabel(self.time)
            self.time_label.setStyleSheet("color: #888888; font-size: 12px;")
            self.time_label.setAlignment(Qt.AlignRight)
        
            layout.addWidget(self.sender_label)
            layout.addWidget(self.message_label)
            layout.addWidget(self.time_label)
            
            self.bubble_container = QWidget()
            bubble_layout = QVBoxLayout(self.bubble_container)
            bubble_layout.setContentsMargins(12, 8, 12, 8)
            bubble_layout.setSpacing(4)
            bubble_layout.addLayout(layout)
            
            base_style = """
                QWidget {
                    border-radius: 8px;
                    padding: 5px;
                }
            """
            
            if self.is_left:
                final_style = base_style + """
                    QWidget {
                        background-color: #424242;
                        margin-right: 50px;
                    }
                """
            else:
                final_style = base_style + """
                    QWidget {
                        background-color: #8E44AD;
                        margin-left: 50px;
                    }
                """
            
            self.bubble_container.setStyleSheet(final_style)
            
            main_layout = QHBoxLayout()
            main_layout.setContentsMargins(0, 0, 0, 0)
            if self.is_left:
                main_layout.addWidget(self.bubble_container)
                main_layout.addStretch()
            else:
                main_layout.addStretch()
                main_layout.addWidget(self.bubble_container)
            
            self.setLayout(main_layout)
        except Exception as e:
            print('6',e)
    
    def show_context_menu(self, pos):
        # 创建右键菜单并设置暗色样式
        menu = QMenu(self)
    
        # 设置菜单样式 - 使用暗色调
        menu.setStyleSheet("""
            QMenu {
                background-color: #424242;
                border: 1px solid #555555;
                padding: 5px;
            }
            QMenu::item {
                background-color: transparent;
                padding: 5px 25px 5px 20px;
                margin: 2px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background-color: #6D2D8D;  
                color: white;
            }
            QMenu::item:disabled {
                color: #777777;
            }
        """)
    
        # 添加复制动作
        copy_action = QAction("复制", self)
        copy_action.triggered.connect(self.copy_message)
        menu.addAction(copy_action)

        reply_action = QAction("回复", self)
        reply_action.triggered.connect(self.reply)
        menu.addAction(reply_action)
    
        # 如果是右侧消息(自己发送的)，添加撤回动作
        if not self.is_left:
            recall_action = QAction("撤回", self)
            recall_action.triggered.connect(self.recall_message)
            menu.addAction(recall_action)
            recall2_action = QAction("撤回并重新编辑", self)
            recall2_action.triggered.connect(self.recall2_message)
            menu.addAction(recall2_action)
    
        # 显示菜单
        menu.exec_(self.mapToGlobal(pos))
    
    def copy_message(self):
        # 复制消息内容(不包括发送者和时间)
        clipboard = QApplication.clipboard()
        clipboard.setText(self.text.replace("\u200B", ""))

    def reply(self):
        full = f"【回复: {self.sender}：{self.text.replace("\u200B", "")}】"
        self.reply_requested.emit(full)
    
    def recall_message(self):
      try:
        global rid
        self.sender = self.sender.split("(")[1].split(")")[0]
        full = f"{self.sender}：{self.text.replace("\u200B", "")}【{self.time}】"
        print(full)
        data = {
            "username": encrypt(username),
            "password": encrypt(password),
            "roomnum": encrypt(rid),
            "message": encrypt(full)
        }
        print(rid)
        r = json.loads(decrypt(p("revokemessage", data)))
        if r['result']=='success':
            # 获取主窗口实例
            main_window = self.window()
            if hasattr(main_window, 'chat_area'):
                if not main_window.chat_area.modify_bubble(full, "【已撤回的内容】"):
                    print(f"未找到匹配的消息气泡: {full}")
            # 更新本地文件
            with open(f"Message {username}/Room{rid}.txt", "r+", encoding='utf-8') as f:
                            content = f.read()
                            f.seek(0)
                            f.write(content.replace(full, f"{self.sender}：【{self.time}】"))
                            f.truncate()
        else:
            QMessageBox.critical(self, 'Lanmei Chat 蓝莓通讯', "撤回失败："+r['result'])
      except Exception as e:
            print(e)

    def recall2_message(self):
      try:
        global rid
        self.sender = self.sender.split("(")[1].split(")")[0]
        full = f"{self.sender}：{self.text.replace("\u200B", "")}【{self.time}】"
        old = self.text.replace("\u200B", "")
        print(full)
        data = {
            "username": encrypt(username),
            "password": encrypt(password),
            "roomnum": encrypt(rid),
            "message": encrypt(full)
        }
        print(rid)
        r = json.loads(decrypt(p("revokemessage", data)))
        if r['result']=='success':
            # 获取主窗口实例
            main_window = self.window()
            if hasattr(main_window, 'chat_area'):
                if not main_window.chat_area.modify_bubble(full, "【已撤回的内容】"):
                    print(f"未找到匹配的消息气泡: {full}")
            # 更新本地文件
            with open(f"Message {username}/Room{rid}.txt", "r+", encoding='utf-8') as f:
                            content = f.read()
                            f.seek(0)
                            f.write(content.replace(full, f"{self.sender}：【{self.time}】"))
                            f.truncate()
            self.reply_requested.emit(old)
        else:
            QMessageBox.critical(self, 'Lanmei Chat 蓝莓通讯', "撤回失败："+r['result'])
      except Exception as e:
            print(e)

    # 添加处理点击的方法
    def handle_message_click(self, event):
      try:
       if event.button() == Qt.LeftButton:
        """处理消息点击事件"""
        if "【文件】" in self.text:
            # 提取文件名
            filename = self.text.replace("【文件】","")
            self.download_file(filename)
        elif "http" in self.text:
            url = extract_first_url(self.text)
            webbrowser.open(url,new=2)
        else:
            # 普通消息点击行为（保持原样）
            super(QLabel, self.message_label).mousePressEvent(event)
      except Exception as e:
            print(e)

    def download_file(self, filename):
      """从FTP服务器下载文件（非图片/视频需确认）"""
      try:
        # 确保 Files 目录存在
        files_dir = Path(f"Files {username}")
        files_dir.mkdir(parents=True, exist_ok=True)
        local_path = files_dir / filename

        # 检查文件扩展名
        file_ext = Path(filename).suffix.lower()
        is_media_file = file_ext in {'.jpg', '.jpeg', '.png', '.gif', 
                                   '.mp4', '.avi', '.mov', '.mkv'}

        # 如果不是媒体文件，询问确认
        if not is_media_file:
            reply = QMessageBox.question(
                self,
                "确认下载",
                f"即将下载文件: {filename}\n文件类型: {file_ext or '未知'}\n是否确认下载？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.No:
                QMessageBox.information(self, "取消下载", "下载已取消")
                return

        # 检查本地文件是否已存在
        if local_path.exists():
            reply = QMessageBox.question(
                self,
                "文件已存在",
                f"文件 '{filename}' 已存在于本地。是否覆盖？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.No:
                QMessageBox.information(self, "取消下载", "文件下载已取消")
                return

        # 连接FTP服务器
        ftp = FTP()
        ftp.connect(ftp_server, ftp_port, timeout=30)
        ftp.login(ftp_username, ftp_password)
        ftp.set_pasv(True)

        # 切换到对应目录
        target_dir = f"/lanmeichat/{rid.replace('#', '')}"
        try:
            ftp.cwd(target_dir)
        except error_perm:
            QMessageBox.warning(self, "下载失败", "文件目录不存在")
            return

        # 设置进度条
        progress = QProgressDialog(f"正在下载 {filename}...", "取消", 0, 100, self)
        progress.setWindowModality(Qt.WindowModal)

        # 获取文件大小
        try:
            file_size = ftp.size(filename)
        except error_perm:
            QMessageBox.warning(self, "下载失败", "文件不存在或无法访问")
            return

        downloaded = 0
        last_progress = 0

        # 关键修正：在with语句外定义文件对象
        f = open(local_path, 'wb')
        
        def callback(data):
            nonlocal downloaded, last_progress
            f.write(data)  # 写入数据到文件
            downloaded += len(data)
            current_progress = int((downloaded / file_size) * 100)
            if current_progress > last_progress:
                progress.setValue(current_progress)
                last_progress = current_progress
                QApplication.processEvents()
            
            if progress.wasCanceled():
                f.close()  # 确保文件关闭
                local_path.unlink()  # 删除不完整文件
                raise Exception("用户取消下载")

        try:
            # 开始下载
            ftp.retrbinary(f"RETR {filename}", callback)
            QMessageBox.information(self, "下载完成", f"文件已保存到: {local_path}")
        finally:
            f.close()  # 确保文件关闭

      except Exception as e:
        if "用户取消下载" not in str(e):
            QMessageBox.critical(self, "错误", f"下载错误: {str(e)}")
        if 'local_path' in locals() and local_path.exists():
            local_path.unlink()
      finally:
        if 'ftp' in locals():
            ftp.quit()
        

class ChatArea(QWidget):
    new_message_signal = pyqtSignal(str, bool)  # 添加这个信号
    resignal = pyqtSignal(str)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.new_message_signal.connect(self._add_message_thread_safe)  # 连接信号
        self.resignal.connect(self.recall_message_son)
        self.setup_ui()

    def handle_reply(self, text):
        """处理回复信号"""
        self.input_field.setText(text + self.input_field.text())

    def _add_message_thread_safe(self, message, is_left):
        """线程安全的消息添加方法"""
        self.add_message(message, is_left)

    def recall_message_son(self,message):
        # 修改气泡内容
        print("收到子线程撤回",message)
        if not self.modify_bubble(message, "【已撤回的内容】"):
            print(f"未找到匹配的消息气泡: {message}")
    
    def setup_ui(self):
        try:
            # 主布局
            self.layout = QVBoxLayout()
            self.layout.setContentsMargins(0, 0, 0, 0)
            self.layout.setSpacing(0)
            '''
            # 欢迎标签（默认显示）
            self.welcome_label = QLabel("蓝莓通讯")
            self.welcome_label.setAlignment(Qt.AlignCenter)
            self.welcome_label.setStyleSheet("""
                QLabel {
                    font-size: 24px;
                    color: #888888;
                    margin-top: 200px;
                }
            """)
            '''
            # 图片显示部分
            self.welcome_label = QLabel()
            self.welcome_label.setAlignment(Qt.AlignCenter)
        
            # 加载图片 (替换为您的图片路径)
            try:
                pixmap = QPixmap(resource_path("lanmeichat.png"))  # 替换为您的图片路径
                if not pixmap.isNull():
                     # 创建圆角遮罩
                    rounded_pixmap = QPixmap(pixmap.size())
                    rounded_pixmap.fill(Qt.transparent)
        
                    painter = QPainter(rounded_pixmap)
                    painter.setRenderHint(QPainter.Antialiasing, True)
                    path = QPainterPath()
                    path.addRoundedRect(0, 0, pixmap.width(), pixmap.height(), 20, 20)
                    painter.setClipPath(path)
                    painter.drawPixmap(0, 0, pixmap)
                    painter.end()
        
                    # 缩放圆角图片到指定宽度
                    rounded_pixmap = rounded_pixmap.scaledToWidth(100, Qt.SmoothTransformation)
                    self.welcome_label.setPixmap(rounded_pixmap)
                else:
                    self.welcome_label.setText("图片加载失败")
                    self.welcome_label.setStyleSheet("color: white; font-size: 16px;")
            except Exception as e:
               self.welcome_label.setText(f"图片加载错误: {str(e)}")
               self.welcome_label.setStyleSheet("color: white; font-size: 16px;")
            
            # 聊天内容区域（初始隐藏）
            self.scroll_area = QScrollArea()
            self.scroll_area.setWidgetResizable(True)
            self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self.scroll_area.hide()  # 初始隐藏
            
            self.chat_content = QWidget()
            self.chat_layout = QVBoxLayout()
            self.chat_layout.setContentsMargins(5, 5, 5, 5)
            self.chat_layout.setSpacing(10)
            self.chat_layout.addStretch()
            
            self.chat_content.setLayout(self.chat_layout)
            self.chat_content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            self.scroll_area.setWidget(self.chat_content)

            self.filebtn = QPushButton()
            self.filebtn.setFixedSize(60, 60)  
            self.filebtn.setIcon(qta.icon("mdi.file",color="white", scale_factor=1.5)) 
            self.filebtn.setStyleSheet("""
                QPushButton {
                    background-color: #8E44AD;  
                    border-radius: 30px;
                    border: none;
                }
                QPushButton:hover {
                    background-color: #9D5CBD; 
                }
                QPushButton:pressed {
                    background-color: #6D2D8D;  
                }
            """)
            
            # 输入区域（初始隐藏）
            self.input_widget = QWidget()
            self.input_layout = QHBoxLayout()
            self.input_layout.setContentsMargins(10, 5, 10, 10)
            
            self.input_field = QLineEdit()
            self.input_field.setPlaceholderText("输入消息...")
            self.input_field.setStyleSheet("""
                QLineEdit {
                    padding: 10px;
                    border-radius: 15px;
                    font-size: 14px;
                }
            """)
            
            self.send_btn = QPushButton()
            self.send_btn.setFixedSize(60, 60)  
            self.send_btn.setIcon(qta.icon("mdi.send",color="white", scale_factor=1.5)) 
            self.send_btn.setStyleSheet("""
                QPushButton {
                    background-color: #8E44AD;  
                    border-radius: 30px;
                    border: none;
                }
                QPushButton:hover {
                    background-color: #9D5CBD; 
                }
                QPushButton:pressed {
                    background-color: #6D2D8D;  
                }
            """)
            
            self.input_layout.addWidget(self.input_field)
            self.input_layout.addWidget(self.send_btn)
            self.input_layout.addWidget(self.filebtn)
            self.input_widget.setLayout(self.input_layout)
            self.input_widget.hide()  # 初始隐藏
            
            # 添加到主布局
            self.layout.addWidget(self.welcome_label)
            self.layout.addWidget(self.scroll_area)
            self.layout.addWidget(self.input_widget)
            
            self.setLayout(self.layout)
        except Exception as e:
            print(e)
    
    def show_chat(self):
        """显示聊天区域"""
        self.welcome_label.hide()
        self.scroll_area.show()
        self.input_widget.show()
    
    def show_welcome(self):
        """显示欢迎标签"""
        self.welcome_label.show()
        self.scroll_area.hide()
        self.input_widget.hide()

    def add_message(self, raw_message, is_left=True):
      try:
        print("add_message开始渲染",raw_message)
        # 默认值
        sender = "未知" if is_left else f"{logindata['name']}({username})"
        message = raw_message
        time = '未知'
        
        # 检查是否是纯时间戳格式（【%Y-%m-%d %H:%M:%S】）
        if extract_core_content(message) == "":
            message = "【已撤回的内容】"
        else:
            # 尝试解析格式化的消息
            try:
                if "：" in raw_message and "【" in raw_message and "】" in raw_message:
                    # 分割发送者
                    sender_part, rest = raw_message.split("：", 1)
                    # 从右侧找到最后一个【和】
                    last_left_bracket = rest.rfind("【")
                    last_right_bracket = rest.rfind("】")
            
                    if last_left_bracket < last_right_bracket:  # 确保【在】左侧
                        time = rest[last_left_bracket+1 : last_right_bracket]
                        sender = namelist.get(sender_part.strip(),"未知")+f"({sender_part.strip()})" if sender_part.strip()!="**系统**" else "**系统**"
                        message = rest[:last_left_bracket].strip()  # 排除时间部分
            except:
                pass
                print("被pass")
        
        # 创建气泡
        bubble = ChatBubble(sender, message, time, is_left)
        bubble.reply_requested.connect(self.handle_reply)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, bubble)
        
        # 智能滚动控制
        scroll_bar = self.scroll_area.verticalScrollBar()
        current_pos = scroll_bar.value()
        max_pos = scroll_bar.maximum()
        
        # 如果当前在底部附近(50像素内)或刚进入聊天室，则滚动到底部
        if abs(current_pos - max_pos) < 50 or is_new_chat:
            QTimer.singleShot(100, lambda: scroll_bar.setValue(max_pos))
        print("完成")
      except Exception as e:
        print("add_message渲染错误",e)
    
    def clear_messages(self):
      try:
        """清除所有消息气泡"""
        # 移除所有非弹簧部件
        while self.chat_layout.count() > 1:  # 保留最后的弹簧
            item = self.chat_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
      except Exception as e:
          print(e)
    def modify_bubble(self, original_text, new_text):
      """通过原始内容查找并修改气泡，改进版"""
      try:
        target_core = extract_core_content(original_text)
        
        # 遍历气泡查找匹配项
        for i in range(self.chat_layout.count() - 1):
            item = self.chat_layout.itemAt(i)
            if item and item.widget() and isinstance(item.widget(), ChatBubble):
                bubble = item.widget()
                bubble_core = extract_core_content(bubble.text)
                
                # 比较核心内容
                if bubble_core == target_core:
                    '''
                    # 保留原始消息的发送者和时间信息（如果有）
                    if "：" in original_text and "【" in original_text:
                        sender_part = original_text.split("：", 1)[0]
                        time_part = original_text[original_text.rfind("【"):]
                        new_display = f"{sender_part}：{new_text}{time_part}"
                    else:
                        '''
                    new_display = new_text
                    
                    # 更新气泡显示
                    bubble.message_label.setText(new_display.replace("", "\u200B")[1:-1])
                    bubble.text = new_display
                    return True
        
        print(f"未找到匹配的气泡 | 原始: {original_text} | 目标核心: {target_core}")
        return False
    
      except Exception as e:
        print(f"修改气泡时出错: {e}")
        return False


class ListItemDelegate(QStyledItemDelegate):
    def __init__(self, parent=None):
        super().__init__(parent)
    
    def sizeHint(self, option, index):
        return QSize(200, 70)
    
    def paint(self, painter, option, index):
        try:
            painter.save()
            
            # 获取当前应用的调色板
            palette = option.palette
            
            # 设置背景色 - 使用调色板颜色
            if option.state & QStyle.State_Selected:
                bg_color = palette.highlight().color()
            elif option.state & QStyle.State_MouseOver:
                bg_color = palette.alternateBase().color()  # 或使用 palette.window().color()
            else:
                bg_color = palette.base().color()
            
            painter.fillRect(option.rect, bg_color)
            
            # 绘制分隔线 - 使用调色板的阴影颜色
            line_color = palette.mid().color()
            painter.setPen(QPen(line_color, 1))
            painter.drawLine(option.rect.bottomLeft(), option.rect.bottomRight())
            
            # 获取数据
            title = index.data(Qt.DisplayRole) or ""
            subtitle = index.data(Qt.UserRole + 1) or ""
            
            # 绘制标题 - 使用调色板文本颜色
            title_font = QFont("Arial", 12, QFont.Bold)
            painter.setFont(title_font)
            painter.setPen(palette.text().color())
            painter.drawText(option.rect.adjusted(15, 10, -15, -30), Qt.AlignLeft | Qt.AlignTop, title)
            
            # 绘制副标题 - 使用调色板弱文本颜色
            subtitle_font = QFont("Arial", 10)
            painter.setFont(subtitle_font)
            painter.setPen(palette.windowText().color())  # 或 palette.mid().color() 更浅的颜色
            painter.drawText(option.rect.adjusted(15, 40, -15, -10), Qt.AlignLeft | Qt.AlignTop, subtitle)
            
            painter.restore()
        except Exception as e:
            print(f"绘制错误: {e}")
            painter.restore()

class ListModel(QAbstractListModel):
    def __init__(self, data=None, parent=None):
        super().__init__(parent)
        self._data = data or []
    
    def rowCount(self, parent=QModelIndex()):
        return len(self._data)
    
    def data(self, index, role=Qt.DisplayRole):
        try:
            if not index.isValid() or index.row() >= len(self._data):
                return ""
            
            item = self._data[index.row()]
            
            if role == Qt.DisplayRole:
                return item.get('title', '')
            elif role == Qt.UserRole + 1:
                return item.get('subtitle', '')
            
            return ""
        except Exception as e:
            print(f"数据获取错误: {e}")
            return ""
    
    def addItem(self, title, subtitle):
        try:
            self.beginInsertRows(QModelIndex(), self.rowCount(), self.rowCount())
            self._data.append({'title': title, 'subtitle': subtitle})
            self.endInsertRows()
        except Exception as e:
            print(f"添加项目错误: {e}")

    def clearAllItems(self):
        """清除所有列表项"""
        try:
            self.beginResetModel()  # 通知视图模型即将重置
            self._data.clear()      # 清空数据
            self.endResetModel()    # 通知视图模型重置完成
        except Exception as e:
            print(f"清除列表项错误: {e}")

class PillButton(QPushButton):
    def __init__(self, text=""):
        super().__init__(text)
        self.setMinimumHeight(40)  # 设置最小高度
        self.setStyleSheet("""
            QPushButton {
                border: none;           /* 移除边框 */
                border-radius: 20px;    /* 圆角半径设置为高度的一半 */
                padding: 0px;          /* 移除内边距，让内容填充整个按钮 */
                margin: 0px;           /* 移除外边距 */
                font-size: 14px;
                background-color: #8E44AD; /* 设置背景色（可选） */
                color: white;           /* 设置文字颜色（可选） */
                min-height: 50px;
            }
            QPushButton:hover {
                background-color: #9D5CBD; /* 悬停状态背景色（可选） */
            }
            QPushButton:pressed {
                background-color: #6D2D8D; /* 按下状态背景色（可选） */
            }
        """)


################################################################主程序###############################################################
logindata={}
class MaterialApp(QMainWindow):
    def __init__(self):
        super().__init__()
        global logindata
        if username == '' or password == '':
            self.initUI()
        else:
            data={
                'username':encrypt(username),
                'password':encrypt(password)}
            result = json.loads(decrypt(p('login',data)))
            if result['result']=='success':
                logindata = result
                self.mainwin()
            else:
                QMessageBox.critical(self, 'Lanmei Chat 蓝莓通讯', "登录验证失败："+result['result']+"，您需要重新登录！")
                self.initUI()
    
    def initUI(self):
        global version
        self.setWindowTitle('Lanmei Chat 蓝莓通讯')
        self.resize(1000, 700)  # 设置窗口大小
        
        # 计算居中位置
        self.center()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(20)

        # 图片显示部分
        image_label = QLabel()
        image_label.setAlignment(Qt.AlignCenter)
        
        # 加载图片 (替换为您的图片路径)
        try:
            pixmap = QPixmap(resource_path("lanmeichat.png"))  # 替换为您的图片路径
            if not pixmap.isNull():
                 # 创建圆角遮罩
                rounded_pixmap = QPixmap(pixmap.size())
                rounded_pixmap.fill(Qt.transparent)
        
                painter = QPainter(rounded_pixmap)
                painter.setRenderHint(QPainter.Antialiasing, True)
                path = QPainterPath()
                path.addRoundedRect(0, 0, pixmap.width(), pixmap.height(), 20, 20)
                painter.setClipPath(path)
                painter.drawPixmap(0, 0, pixmap)
                painter.end()
        
                # 缩放圆角图片到指定宽度
                rounded_pixmap = rounded_pixmap.scaledToWidth(100, Qt.SmoothTransformation)
                image_label.setPixmap(rounded_pixmap)
            else:
                image_label.setText("图片加载失败")
                image_label.setStyleSheet("color: white; font-size: 16px;")
        except Exception as e:
            image_label.setText(f"图片加载错误: {str(e)}")
            image_label.setStyleSheet("color: white; font-size: 16px;")

                
        title = QLabel("Lanmei Chat 蓝莓通讯")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold;")

        subtitle = QLabel("Windows客户端"+version)
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("font-size: 18px;")

        context = QLabel("欢迎使用蓝莓通讯，我们立志回归本质，做一个纯粹的聊天软件。本软件由张蓝莓、增稠剂、摸鱼真君三位初中生联合开发。此版本是开源版本。我们的官网：lanmei.chat\n\n我们注重您的隐私。您需要了解，您的账号、密码、聊天记录会储存在本地和服务器上，聊天记录会定期清理，密码采用不可逆加密存储。您可以随时要求我们把服务器上关于您的任何信息直接删除，我们绝不会将您的个人信息以任何形式分享给第三方（账号互通服务及我国法律法规规定除外）。\n\n我们尊重用户自定义他们的蓝莓通讯。您可以对本软件进行逆向、修改源代码的行为，或开发相关XP插件，以获得特定功能。因此，我们的客户端不会添加任何加固、签较和混淆。您可以向他人分享您修改的版本，但绝不能售卖或抹除原作者信息，也不能复制本软件的源代码去自制产品。您可以发现并利用蓝莓通讯的API漏洞，但不要盗刷流量或获取其他用户的信息。我们更希望您能反馈漏洞，这样您甚至可以加入开发团队，共同开发与优化。\n\n请勿使用本软件从事任何可能违反我国法律法规的行为，因使用此软件所造成的任何责任与损失都与开发团队无关。如您的防护软件报毒，请直接忽略，我们绝不会添加任何病毒代码。\n\n感谢您选择蓝莓通讯，把此文件复制到你喜欢的目录（本软件会在软件目录下保存配置文件），然后点击“确定”，开始奇妙之旅吧！")
        context.setAlignment(Qt.AlignCenter)
        context.setStyleSheet("font-size: 18px;text-align: left;")
        context.setFixedWidth(900)  
        context.setWordWrap(True)  # 启用自动换行
        
        # 创建药丸形状按钮
        button_container = QWidget()
        button_layout = QHBoxLayout()  # 改为水平布局(QHBoxLayout)
        button_layout.setSpacing(15)  # 设置按钮间距
        button_container.setLayout(button_layout)
        
        primary_btn = PillButton("退出")
        primary_btn.clicked.connect(self.on_primary_click)
        secondary_btn = PillButton("确定")
        secondary_btn.clicked.connect(self.startlogin)
        button_layout.addWidget(primary_btn)
        button_layout.addWidget(secondary_btn)

        layout.addWidget(image_label)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(context)
        layout.addWidget(button_container)
        
        central_widget.setLayout(layout)
    
    def center(self):
        """将窗口居中显示"""
        # 获取屏幕的几何信息
        screen = QApplication.primaryScreen().availableGeometry()
        # 获取窗口的几何信息
        size = self.geometry()
        # 计算居中位置
        self.move(
            (screen.width() - size.width()) // 2,
            (screen.height() - size.height()) // 2
        )
    def on_primary_click(self):
        os._exit(1)

    def startlogin(self):
      try:
        with open("config.txt", "r", encoding='utf-8') as file:
            config = json.load(file)
      except FileNotFoundError:
        config = {}
        configsave()
        print("config创建完成！")
      except Exception as e:
        QMessageBox.critical(self, 'Lanmei Chat - 错误', e)
        tmpapp.exec_()
        os._exit(1)
      try:
        # 清除旧布局（防止内存泄漏）
        old_central = self.centralWidget()
        if old_central:
            old_central.deleteLater()
        
        self.setWindowTitle('Lanmei Chat - 登录/注册')
        self.resize(1000, 700)  # 设置窗口大小
        
        # 计算居中位置
        self.center()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        self.layout = QVBoxLayout()
        self.layout.setAlignment(Qt.AlignCenter)
        self.layout.setSizeConstraint(QLayout.SetMinimumSize)
        self.layout.setSpacing(20)
        self.layout.setContentsMargins(50, 0, 50, 0)# 左, 上, 右, 下
         

        # 图片显示部分
        image_label = QLabel()
        image_label.setAlignment(Qt.AlignCenter)
        
        # 加载图片 (替换为您的图片路径)
        try:
            pixmap = QPixmap(resource_path("lanmeichat.png"))  # 替换为您的图片路径
            if not pixmap.isNull():
                 # 创建圆角遮罩
                rounded_pixmap = QPixmap(pixmap.size())
                rounded_pixmap.fill(Qt.transparent)
        
                painter = QPainter(rounded_pixmap)
                painter.setRenderHint(QPainter.Antialiasing, True)
                path = QPainterPath()
                path.addRoundedRect(0, 0, pixmap.width(), pixmap.height(), 20, 20)
                painter.setClipPath(path)
                painter.drawPixmap(0, 0, pixmap)
                painter.end()
        
                # 缩放圆角图片到指定宽度
                rounded_pixmap = rounded_pixmap.scaledToWidth(100, Qt.SmoothTransformation)
                image_label.setPixmap(rounded_pixmap)
            else:
                image_label.setText("图片加载失败")
                image_label.setStyleSheet("color: white; font-size: 16px;")
        except Exception as e:
            image_label.setText(f"图片加载错误: {str(e)}")
            image_label.setStyleSheet("color: white; font-size: 16px;")

                
        title = QLabel("登录/注册")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold;")

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("用户名 (用于区分账号，注册后不可修改)")
        self.username_input.setStyleSheet("""
          QLineEdit {
            padding: 10px;
            font-size: 14px;
            border: 2px solid #000000;
            border-radius: 20px;
            min-height: 40px;
            margin: 0 15px;
          }
        """)
        self.username_input.setFixedWidth(850) 
        self.username_input.editingFinished.connect(self.on_text_changed)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("名称 (用于显示，可以随便改。登录时输入用户名会自动填充，注册时需手动输入)")
        self.name_input.setStyleSheet("""
          QLineEdit {
            padding: 10px;
            font-size: 14px;
            border: 2px solid #000000;
            border-radius: 20px;
            min-height: 40px;
            margin: 0 15px;
          }
        """)
        self.name_input.setFixedWidth(850) 

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("请输入密码")
        self.password_input.setEchoMode(QLineEdit.Password)  # 密码输入模式
        self.password_input.setStyleSheet("""
          QLineEdit {
            padding: 10px;
            font-size: 14px;
            border: 2px solid #000000;
            border-radius: 20px;
            min-height: 40px;
            margin: 0 15px;
          }
        """)
        self.password_input.setFixedWidth(850) 

        self.password_confirm = QLineEdit()
        self.password_confirm.setPlaceholderText("请再次输入密码，以确认您已记住密码")
        self.password_confirm.setEchoMode(QLineEdit.Password)  # 密码输入模式
        self.password_confirm.setStyleSheet("""
          QLineEdit {
            padding: 10px;
            font-size: 14px;
            border: 2px solid #000000;
            border-radius: 20px;
            min-height: 40px;
            margin: 0 15px;
          }
        """)
        self.password_confirm.setFixedWidth(850) 
        self.password_confirm.hide()
        
        # 按钮
        button_container = QWidget()
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)

        register_btn = PillButton("注册")
        register_btn.clicked.connect(self.signup) 
        login_btn = PillButton("登录")
        login_btn.clicked.connect(self.login)

        button_layout.addWidget(register_btn)
        button_layout.addWidget(login_btn)
        button_container.setLayout(button_layout)

        # 添加组件到布局
        self.layout.addWidget(image_label)
        self.layout.addWidget(title)
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.name_input)
        self.layout.addWidget(self.password_confirm)  # 即使隐藏也加入布局
        self.layout.addWidget(button_container)

        central_widget.setLayout(self.layout)
      except Exception as e:
          print(e)

    def on_text_changed(self):
      try:
        result = decrypt(r('getname/["'+self.username_input.text()+'"]'))
        self.name_input.setText(ast.literal_eval(result)[0])
      except Exception as e:
          print(e)


    def signup(self):
     try:
      if self.password_confirm.isHidden():
            self.password_confirm.show()
      else:
        if self.username_input.text() != '' and self.name_input.text() != '' and self.password_input.text() != '' and self.password_input.text()==self.password_confirm.text():
            data = {
                "username": encrypt(self.username_input.text()),
                "name": encrypt(self.name_input.text()),
                "password": encrypt(self.password_input.text())
            }
            result = json.loads(decrypt(p('signup',data)))
            if result['result'] == 'success':
                QMessageBox.information(self, 'Lanmei Chat - 注册', '注册成功！请牢记您的用户名和密码，然后点击登录即可。')
                self.password_confirm.hide()
            else:
                QMessageBox.information(self, 'Lanmei Chat - 注册', '注册失败！'+result['result'])
        else:
            QMessageBox.information(self, 'Lanmei Chat - 注册', '注册失败！请确保所有输入框均不为空，并且两次输入密码一致。')
     except Exception as e:
          print(e)

    def login(self):
        try:
            global logindata,username,password
            self.password_confirm.hide()
            if self.username_input.text() != '' and self.name_input.text() != '' and self.password_input.text() != '':
                data = {
                    "username": encrypt(self.username_input.text()),
                    "password": encrypt(self.password_input.text())
                }
                result = json.loads(decrypt(p('login',data)))
                if result['result'] == 'success':
                    config["username"]=sencrypt(self.username_input.text())
                    config["password"]=sencrypt(self.password_input.text())
                    configsave()
                    #QMessageBox.information(self, 'Lanmei Chat - 登录', '登录成功！')
                    #app.exec_()
                    logindata = result
                    username = self.username_input.text()
                    password = self.password_input.text()
                    self.mainwin()
                    if not os.path.exists(f"Message {username}"):
                        os.makedirs(f"Message {username}")
                        print('Message文件夹已创建')
                else:
                    QMessageBox.information(self, 'Lanmei Chat - 登录', '登录失败！'+result['result'])
            else:
                QMessageBox.information(self, 'Lanmei Chat - 登录', '登录失败！请确保所有输入框均不为空。')
        except Exception as e:
            print(e)

    def mainwin(self):
      global logindata
      try:
        # 清除旧布局
        old_central = self.centralWidget()
        if old_central:
            old_central.deleteLater()
        
        self.setWindowTitle('Lanmei Chat 蓝莓通讯')
        self.resize(1000, 700)
        self.center()

        # 创建主容器
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 使用水平布局，左侧是列表视图，右侧是内容区域
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 左侧区域
        left_widget = QWidget()
        left_widget.setFixedWidth(350)
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        # 列表视图
        self.list_view = QListView()
        self.list_view.setItemDelegate(ListItemDelegate(self.list_view))
        self.list_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.list_view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.list_view.setStyleSheet("""
            QListView {
                border: none;
            }
            QListView::item {
                border: none;
            }
        """)
        
        # 创建模型并填充数据
        self.list_model = ListModel()
        self.populate_list_data()
        self.list_view.setModel(self.list_model)
        
        left_layout.addWidget(self.list_view)

        selection_model = self.list_view.selectionModel()
        if selection_model:
            selection_model.selectionChanged.connect(self.on_list_selection_changed)
        else:
            print("Warning: 无法获取列表的选择模型")

        # 左下角个人中心 - 修改样式
        user_info_widget = QWidget()
        user_info_widget.setStyleSheet("background-color: #424242;")  # 与列表背景色一致
        user_info_layout = QHBoxLayout(user_info_widget)
        user_info_layout.setContentsMargins(10, 5, 10, 5)
        user_info_layout.setAlignment(Qt.AlignVCenter)
        
        # 用户名标签
        self.ns = QLabel(logindata.get('name', '未知用户'))
        self.ns.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.ns.setStyleSheet("""
            font-size: 16px; 
            color: white;
            padding-left: 5px;
        """)
        
        # 按钮容器
        button_container = QWidget()
        button_container.setStyleSheet("background-color: transparent;")
        button_layout = QHBoxLayout(button_container)
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(5)
        
        # 添加按钮 (绿色加号按钮)
        add_btn = QPushButton()
        add_btn.setFixedSize(60, 60)  # 稍微减小按钮尺寸
        add_btn.setIcon(qta.icon("mdi.plus", scale_factor=2.5))  # 使用系统加号图标
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                border-radius: 30px;
                border: none;
            }
            QPushButton:hover {
                background-color: #66BB6A;
            }
            QPushButton:pressed {
                background-color: #388E3C;
            }
        """)
        add_btn.clicked.connect(self.open_add_window)
        
        # 用户按钮 (黄色人头按钮)
        user_btn = QPushButton()
        user_btn.setFixedSize(60, 60)
        user_btn.setIcon(qta.icon("mdi.account-circle", scale_factor=1.3))  # 使用系统用户图标
        user_btn.setStyleSheet("""
            QPushButton {
                background-color: #FFC107;
                border-radius: 30px;
                border: none;
            }
            QPushButton:hover {
                background-color: #FFD54F;
            }
            QPushButton:pressed {
                background-color: #FFA000;
            }
        """)
        user_btn.clicked.connect(self.open_user_window)
        
        # 群聊管理)
        quit_btn = QPushButton()
        quit_btn.setFixedSize(60, 60)
        quit_btn.setIcon(qta.icon("mdi.cog", scale_factor=1.3))  
        quit_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;  /* 蓝色 */
                color: white;              /* 文字颜色 */
                border-radius: 30px;
                border: none;
            }
            QPushButton:hover {
                background-color: #42A5F5;  /* 悬停时浅蓝色 */
            }
            QPushButton:pressed {
                background-color: #1976D2;  /* 按下时深蓝色 */
            }
        """)
        quit_btn.clicked.connect(self.chatinfo)
        
        button_layout.addWidget(add_btn)
        button_layout.addWidget(user_btn)
        button_layout.addWidget(quit_btn)
        
        user_info_layout.addWidget(self.ns)
        user_info_layout.addWidget(button_container)
        user_info_layout.setStretch(0, 1)
        left_layout.addWidget(user_info_widget)
        
        # 设置左侧整体背景色
        left_widget.setStyleSheet("background-color: #424242;")
        self.list_view.setStyleSheet("""
            QListView {
                background-color: #424242;
                border: none;
                color: white;
            }
            QListView::item {
                background-color: #424242;
                border: none;
                color: white;
            }
            QListView::item:hover {
                background-color: #555555;
            }
            QListView::item:selected {
                background-color: #1976D2;
            }
        """)
        
        # 右侧内容区域
        self.chat_area = ChatArea()
        self.chat_area.show_welcome() 

        # 连接发送按钮
        self.chat_area.send_btn.clicked.connect(self.send_message)
        self.chat_area.filebtn.clicked.connect(self.send_file)
        self.chat_area.input_field.returnPressed.connect(self.send_message)
        
        # 将左右两部分添加到主布局
        main_layout.addWidget(left_widget)
        main_layout.addWidget(self.chat_area)
        
        central_widget.setLayout(main_layout)

        # 登录刷新（接收消息）
        self.stop_login = False
        self.login_thread = threading.Thread(target=self.uplogin)
        self.login_thread.daemon = True
        self.login_thread.start()
        
        # 显示主窗口
        self.show()
        
        if logindata.get("ask", {})!={}:
            self.show_ask_dialog()
            
      except Exception as e:
        print(f"主界面初始化错误: {e}")
        QMessageBox.critical(self, '错误', f'主界面错误: {str(e)}')

    def show_ask_dialog(self):
      print(logindata["ask"])
      """显示询问对话框"""
      reply = QMessageBox.question(
        self, '新的确认消息', 
        "您有新的好友/聊天室确认消息/聊天室邀请，是否查看？",
        QMessageBox.Yes | QMessageBox.No, 
        QMessageBox.No
      )
      if reply == QMessageBox.Yes:
        self.open_add_window()

    def uplogin(self):
        try:
            global logindata
            while not self.stop_login:
                for _ in range(45): 
                    if self.stop_login:
                        return
                    time.sleep(0.1)
                print("登录一次")
                data = {
                    "username": encrypt(username),
                    "password": encrypt(password)
                }
                result = json.loads(decrypt(p('login',data)))
                
                if result['result'] == 'success':
                        #if result != logindata:
                        logindata = result
                        self.populate_list_data()
                        self.ns.setText(logindata.get('name', '未知用户'))
                else:
                    QMessageBox.information(self, 'Lanmei Chat - 登录', '登录失败！'+result['result'])
        except Exception as e:
            QMessageBox.critical(self, '错误', f'持续登录错误: {str(e)}')

    def chatinfo(self):###@@
      """显示群聊信息界面"""
      try:
        global is_owner
        is_owner = False
        # 检查当前是否是群聊
        if not hasattr(self, 'room_id') or not self.room_id.startswith('#'):
            QMessageBox.information(self, '提示', '这是群聊信息，请选择一个群聊！')
            return

        # 创建群聊信息窗口
        info_window = QDialog(self)
        info_window.setWindowTitle(f"群聊设置 - {self.room_name} {self.room_id}")
        info_window.resize(600, 600)
        self.center()
        
        # 主布局
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # 1. 群号标题 (带图标)
        group_id_layout = QHBoxLayout()
        group_id_layout.setSpacing(10)
        group_id_icon = qta.icon("mdi.account-group", color="#2196F3")
        group_id_label = QLabel()
        group_id_label.setPixmap(group_id_icon.pixmap(24, 24))
        group_id_title = QLabel("群号:")
        group_id_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        group_id_value = QLabel(self.room_id)
        group_id_value.setStyleSheet("font-size: 16px;")
        
        group_id_layout.addWidget(group_id_label)
        group_id_layout.addWidget(group_id_title)
        group_id_layout.addWidget(group_id_value)
        group_id_layout.addStretch()
        layout.addLayout(group_id_layout)
        
        # 2. 群名称修改 (带图标)
        group_name_layout = QHBoxLayout()
        group_name_layout.setSpacing(10)
        name_icon = qta.icon("mdi.rename-box", color="#2196F3")
        name_label = QLabel()
        name_label.setPixmap(name_icon.pixmap(24, 24))
        name_title = QLabel("群名称:")
        name_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        
        self.group_name_edit = QLineEdit(self.room_name)
        self.group_name_edit.setStyleSheet("""
          QLineEdit {
            font-size: 14px;
            border: 2px solid #000000;
            border-radius: 25px;
            min-height: 50px;
            margin: 0 0;
          }
        """)
        
        save_name_btn = QPushButton()
        save_name_btn.setFixedSize(50, 50)
        save_name_btn.setIcon(qta.icon("fa5s.check", color="white"))
        save_name_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #4CAF50;
                            border-radius: 25px;
                            border: none;
                        }
                        QPushButton:hover {
                            background-color: #66BB6A;
                        }
        """)
        save_name_btn.clicked.connect(lambda: self.save_group_name(self.group_name_edit.text()))
        
        group_name_layout.addWidget(name_label)
        group_name_layout.addWidget(name_title)
        group_name_layout.addWidget(self.group_name_edit)
        group_name_layout.addWidget(save_name_btn)
        layout.addLayout(group_name_layout)
        
        # 3. 成员列表 (带图标)
        members_layout = QVBoxLayout()
        members_layout.setSpacing(10)
        
        members_title_layout = QHBoxLayout()
        members_icon = qta.icon("mdi.account-multiple", color="#2196F3")
        members_label = QLabel()
        members_label.setPixmap(members_icon.pixmap(24, 24))
        members_title = QLabel("群成员:")
        members_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        
        members_title_layout.addWidget(members_label)
        members_title_layout.addWidget(members_title)
        members_title_layout.addStretch()
        members_layout.addLayout(members_title_layout)
        
        # 成员列表视图
        self.member_list = QListView()
        self.member_list.setItemDelegate(ListItemDelegate(self.member_list))
        self.member_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.member_list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.member_list.setStyleSheet("""
            QListView {
                border: 1px solid #555;
                border-radius: 5px;
                background-color: #424242;
            }
        """)
        
        # 获取群成员数据
        self.member_model = ListModel()
        self.load_group_members()
        self.member_list.setModel(self.member_model)
        self.member_list.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.member_list.setMinimumHeight(200)
        
        # 成员列表右键菜单
        self.member_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.member_list.customContextMenuRequested.connect(self.show_member_menu)
        
        members_layout.addWidget(self.member_list)
        layout.addLayout(members_layout)
        
        # 4. 邀请新成员 (带图标)
        invite_layout = QVBoxLayout()
        invite_layout.setSpacing(10)
        
        invite_title_layout = QHBoxLayout()
        invite_icon = qta.icon("mdi.account-plus", color="#2196F3")
        invite_label = QLabel()
        invite_label.setPixmap(invite_icon.pixmap(24, 24))
        invite_title = QLabel("邀请新成员:")
        invite_title.setStyleSheet("font-size: 16px; font-weight: bold;")
        
        invite_title_layout.addWidget(invite_label)
        invite_title_layout.addWidget(invite_title)
        invite_title_layout.addStretch()
        invite_layout.addLayout(invite_layout)
        
        # 邀请输入框和按钮
        self.invite_input = QLineEdit()
        self.invite_input.setPlaceholderText("输入要邀请的用户名（多个用空格隔开）")
        self.invite_input.setStyleSheet("""
          QLineEdit {
            font-size: 14px;
            border: 2px solid #000000;
            border-radius: 25px;
            min-height: 50px;
            margin: 0 0;
          }
        """)
        
        invite_btn = QPushButton()
        invite_btn.setFixedSize(50, 50)  # 稍微减小按钮尺寸
        invite_btn.setIcon(qta.icon("mdi.send",color="white", scale_factor=1.5))  # 使用系统加号图标
        invite_btn.setStyleSheet("""
                QPushButton {
                    background-color: #8E44AD;  
                    border-radius: 25px;
                    border: none;
                }
                QPushButton:hover {
                    background-color: #9D5CBD; 
                }
                QPushButton:pressed {
                    background-color: #6D2D8D;  
                }
        """)
        invite_btn.clicked.connect(self.send_invitation)
        
        invite_input_layout = QHBoxLayout()
        invite_input_layout.addWidget(self.invite_input)
        invite_input_layout.addWidget(invite_btn)
        invite_layout.addLayout(invite_input_layout)
        
        layout.addLayout(invite_layout)

        q = PillButton("退出群聊")
        q.setIcon(qta.icon("mdi.logout", color="white"))
        layout.addWidget(q)
        q.clicked.connect(self.quitr)

        dd = QPushButton("删除群聊")
        dd.setIcon(qta.icon("mdi.delete", color="white"))
        dd.setStyleSheet("""
            QPushButton {
                border: none;
                border-radius: 20px;
                padding: 0px;
                margin: 0px;
                font-size: 14px;
                background-color: #F44336;  /* Material Red 500 */
                color: white;
                min-height: 50px;
            }
            QPushButton:hover {
                background-color: #EF5350;  /* Material Red 400 (更亮) */
            }
            QPushButton:pressed {
                background-color: #D32F2F;  /* Material Red 700 (更暗) */
            }
        """)
        
        if is_owner:
            layout.addWidget(dd)
            dd.clicked.connect(self.delr)
        
        # 添加弹簧使内容顶部对齐
        layout.addStretch()
        
        info_window.setLayout(layout)
        info_window.exec_()
        
      except Exception as e:
        print(f"显示群聊信息错误: {e}")
        QMessageBox.critical(self, '错误', f'显示群聊信息失败: {str(e)}')

    def quitr(self):
        try:
          reply = QMessageBox.question(
                self, '确认退出', 
                f"是否确认退出群聊？您可在该程序文件夹下/Message查看聊天记录",
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.No
          )
        
          if reply == QMessageBox.Yes:
            data={
                "username": encrypt(username),
                "password": encrypt(password),
                "roomnum": encrypt(self.room_id)}
            rrs = json.loads(decrypt(p("quitroom", data)))["result"]
            QMessageBox.information(self, 'Lanmei Chat - 蓝莓通讯', rrs)
        except Exception as e:
            QMessageBox.critical(self, '错误', str(e))

    def delr(self):
        try:
          reply = QMessageBox.question(
                self, '确认删除', 
                f"是否确认删除群聊？您可在该程序文件夹下/Message查看聊天记录",
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.No
          )
        
          if reply == QMessageBox.Yes:
            data={
                "username": encrypt(username),
                "password": encrypt(password),
                "roomnum": encrypt(self.room_id)}
            rrs = json.loads(decrypt(p("deleteroom", data)))["result"]
            QMessageBox.information(self, 'Lanmei Chat - 蓝莓通讯', rrs)
        except Exception as e:
            QMessageBox.critical(self, '错误', str(e))

    
    def load_group_members(self):
      """加载群成员列表"""
      try:
        global is_owner
        self.member_model.clearAllItems()
        data = {
            "username": encrypt(username),
            "password": encrypt(password),
            "roomnum": encrypt(self.room_id)
        }
        rrs = json.loads(decrypt(p("getroommember", data)))
        print(rrs)
        if rrs["result"]=="success":
            members = json.loads(rrs["members"])
            is_owner = rrs["is_owner"]
            members[next(iter(members))]="(群主) "+members[next(iter(members))]
            print(members)
            for i,j in members.items():
                self.member_model.addItem(i,j)
        else:
            QMessageBox.critical(self, '错误', rrs["result"])
      except Exception as e:
        print(f"加载群成员错误: {e}")
        QMessageBox.critical(self, '错误', f'加载群成员失败: {str(e)}')

    def show_member_menu(self, pos):
      """显示成员右键菜单"""
      try:
        global is_owner
        index = self.member_list.indexAt(pos)
        if not index.isValid():
            return
    
        selected_member = self.member_model._data[index.row()]["subtitle"]#获取点击的用户名
        # 移除"(群主)"标记获取真实用户名
        member_name = selected_member.replace("(群主) ", "")
        
        # 创建菜单
        menu = QMenu()
        menu.setStyleSheet("""
            QMenu {
                background-color: #424242;
                color: white;
                border: 1px solid #555;
            }
            QMenu::item:selected {
                background-color: #6D2D8D;
            }
        """)
        if member_name != username:
            # 添加好友动作
            add_friend_action = QAction(qta.icon("mdi.account-plus"), "加为好友", self)
            add_friend_action.triggered.connect(lambda: self.add_friend(member_name))
            menu.addAction(add_friend_action)
    
            # 只有群主才能看到这些选项
            if is_owner:
                menu.addSeparator()
        
                # 踢出群聊动作
                kick_action = QAction(qta.icon("mdi.account-remove"), "踢出群聊", self)
                kick_action.triggered.connect(lambda: self.kick_member(member_name))
                menu.addAction(kick_action)
        
                # 设为群主动作 (如果不是当前用户)
                set_owner_action = QAction(qta.icon("mdi.crown"), "设为群主", self)
                set_owner_action.triggered.connect(lambda: self.set_as_owner(member_name))
                menu.addAction(set_owner_action)
    
            menu.exec_(self.member_list.viewport().mapToGlobal(pos))
      except Exception as e:
        print(f"加载右键菜单错误: {e}")

    def add_friend(self, member_name):
      """加为好友"""
      try:
        text, ok = QInputDialog.getText(
            self,                      # 父窗口（None 表示无父窗口）
            "添加好友"+member_name,                # 窗口标题
            f"输入您的自我介绍：（您在{self.room_name} {self.room_id}）"
        )
        
        if ok:
            data = {
                "username": encrypt(username),
                "password": encrypt(password),
                "friendUsername": encrypt(member_name),
                "introduction": encrypt(f"{text}(来自{self.room_name} {self.room_id})")
            }
            result = json.loads(decrypt(p("adduser", data)))
            QMessageBox.information(self, "结果", result["result"])
    
      except Exception as e:
        print(f"添加好友错误: {e}")
        QMessageBox.critical(self, '错误', f'添加好友失败: {str(e)}')

    def kick_member(self, member_name):
      """踢出群成员"""
      try:
        reply = QMessageBox.question(
            self, '确认踢出成员', 
            f"是否确认将 {member_name} 踢出群聊?",
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            data = {
                "username": encrypt(username),
                "password": encrypt(password),
                "roomnum": encrypt(self.room_id),
                "waitinguser": encrypt(member_name)
            }
            result = json.loads(decrypt(p("kickfromroom", data)))
            QMessageBox.information(self, "结果", result["result"])
            
            # 刷新成员列表
            if result["result"] == "踢出成员成功":
                self.load_group_members()
    
      except Exception as e:
        print(f"踢出成员错误: {e}")
        QMessageBox.critical(self, '错误', f'踢出成员失败: {str(e)}')

    def set_as_owner(self, member_name):
      """设为群主"""
      try:
        reply = QMessageBox.question(
            self, '确认转让群主', 
            f"是否确认将群主转让给 {member_name}?",
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            data = {
                "username": encrypt(username),
                "password": encrypt(password),
                "roomnum": encrypt(self.room_id),
                "newowner": encrypt(member_name)
            }
            result = json.loads(decrypt(p("changeowner", data)))
            QMessageBox.information(self, "结果", result["result"])
            
            # 刷新成员列表
            if result["result"] == "转让群主成功！":
                self.load_group_members()
    
      except Exception as e:
        print(f"转让群主错误: {e}")
        QMessageBox.critical(self, '错误', f'转让群主失败: {str(e)}')

    def save_group_name(self, new_name):
      """保存群名称修改"""
      try:
        if not new_name or new_name == self.room_name:
            QMessageBox.warning(self, "蓝莓通讯", "您好像没改名字？")
            return
            
        data = {
            "username": encrypt(username),
            "password": encrypt(password),
            "roomnum": encrypt(self.room_id),
            "newname": encrypt(new_name)
        }
        result = json.loads(decrypt(p("changeroomname", data)))
        
        if result["result"] == "修改名称完成！":
            self.room_name = new_name
            QMessageBox.information(self, "成功", "群名称已更新")
            # 更新主窗口列表中的群名称
            self.update_room_name_in_list()
        else:
            QMessageBox.warning(self, "失败", result["result"])
    
      except Exception as e:
        print(f"保存群名称错误: {e}")
        QMessageBox.critical(self, '错误', f'保存群名称失败: {str(e)}')

    def send_invitation(self):
      """发送群邀请"""
      try:
        invitee = self.invite_input.text().strip()
        if not invitee:
            QMessageBox.warning(self, "警告", "请输入要邀请的用户名")
            return
            
        text, ok = QInputDialog.getText(
            self,                      # 父窗口（None 表示无父窗口）
            "邀请好友",                # 窗口标题
            f"输入您对该群聊的介绍：（您在{self.room_name} {self.room_id}）"
        )
        
        if ok:
            data = {
                "username": encrypt(username),
                "password": encrypt(password),
                "roomnum": encrypt(self.room_id),
                "users": encrypt(invitee),
                "introduction": encrypt(f"(邀请者:{namelist.get(username,"未知用户")}({username})){text}")
            }
            result = json.loads(decrypt(p("invitetoroom", data)))
            QMessageBox.information(self, "结果", result["result"])
            self.invite_input.clear()
    
      except Exception as e:
        print(f"发送邀请错误: {e}")
        QMessageBox.critical(self, '错误', f'发送邀请失败: {str(e)}')

    def update_room_name_in_list(self):
      """在主窗口列表中更新群名称"""
      try:
        for i in range(self.list_model.rowCount()):
            if self.list_model._data[i]["title"].endswith(self.room_id):
                self.list_model._data[i]["title"] = f"{self.room_name} {self.room_id}"
                self.list_model.dataChanged.emit(
                    self.list_model.index(i), 
                    self.list_model.index(i)
                )
                break
      except Exception as e:
        print(f"更新列表中的群名称错误: {e}")

        
    def open_add_window(self):
      """打开加号按钮对应的新窗口"""
      try:
        add_window = QMainWindow(self)
        add_window.setWindowTitle("Lanmei Chat - 添加好友/聊天室")
        add_window.resize(900, 1000)
        
        # 主窗口布局
        central_widget = QWidget()
        add_window.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(20)
        
        # 左侧：申请卡片区域
        left_widget = QWidget()
        left_widget.setMinimumWidth(400)
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        # 申请卡片标题
        requests_label = QLabel("好友/聊天室申请")
        requests_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                padding: 10px;
                border-bottom: 1px solid #555;
            }
        """)
        left_layout.addWidget(requests_label)
        
        # 滚动区域
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        
        # 卡片容器
        cards_container = QWidget()
        cards_layout = QVBoxLayout(cards_container)
        cards_layout.setContentsMargins(5, 5, 5, 5)
        cards_layout.setSpacing(15)
        
        # 数据
        request_data = logindata["ask"]
        
        # 创建卡片
        for title, users in request_data.items():
            # 卡片外框
            card = QWidget()
            card.setStyleSheet("""
                QWidget {
                    background-color: #424242;
                    border-radius: 8px;
                    padding: 5px;
                }
            """)
            card.title = title  # 存储卡片标题
            
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(0, 0, 0, 0)
            
            # 卡片标题
            title_label = QLabel(title)
            title_label.setStyleSheet("""
                QLabel {
                    font-size: 16px;
                    font-weight: bold;
                    padding: 8px;
                    border-bottom: 1px solid #555;
                }
            """)
            card_layout.addWidget(title_label)
            
            # 用户列表
            for user_info in users:
                for user, intro in user_info.items():
                    # 主用户信息容器
                    user_container = QWidget()
                    user_container.user = user  # 存储用户名
                    user_container_layout = QVBoxLayout(user_container)
                    user_container_layout.setContentsMargins(10, 5, 10, 5)
                    user_container_layout.setSpacing(5)
                    
                    # 用户名行
                    user_widget = QWidget()
                    user_layout = QHBoxLayout(user_widget)
                    user_layout.setContentsMargins(0, 0, 0, 0)
                    
                    # 用户信息
                    user_label = QLabel(user)
                    user_label.setStyleSheet("font-size: 14px;")
                    
                    # 操作按钮
                    btn_container = QWidget()
                    btn_layout = QHBoxLayout(btn_container)
                    btn_layout.setContentsMargins(0, 0, 0, 0)
                    btn_layout.setSpacing(5)
                    
                    accept_btn = QPushButton()
                    accept_btn.setFixedSize(30, 30)
                    accept_btn.setIcon(qta.icon("fa5s.check", color="white"))
                    accept_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #4CAF50;
                            border-radius: 15px;
                            border: none;
                        }
                        QPushButton:hover {
                            background-color: #66BB6A;
                        }
                    """)
                    # 连接信号，传递卡片和用户信息
                    accept_btn.clicked.connect(
                        lambda checked, c=card, u=user_container: 
                        self.handle_request(c, u, True)
                    )
                    
                    reject_btn = QPushButton()
                    reject_btn.setFixedSize(30, 30)
                    reject_btn.setIcon(qta.icon("fa5s.times", color="white"))
                    reject_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #F44336;
                            border-radius: 15px;
                            border: none;
                        }
                        QPushButton:hover {
                            background-color: #EF5350;
                        }
                    """)
                    # 连接信号，传递卡片和用户信息
                    reject_btn.clicked.connect(
                        lambda checked, c=card, u=user_container: 
                        self.handle_request(c, u, False)
                    )
                    
                    btn_layout.addWidget(accept_btn)
                    btn_layout.addWidget(reject_btn)
                    
                    user_layout.addWidget(user_label)
                    user_layout.addWidget(btn_container)
                    
                    # 自我介绍行
                    intro_label = QLabel(f"{intro}")
                    intro_label.setStyleSheet("""
                        QLabel {
                            font-size: 12px;
                            color: #AAAAAA;
                            padding-left: 5px;
                        }
                    """)
                    
                    # 添加到容器
                    user_container_layout.addWidget(user_widget)
                    user_container_layout.addWidget(intro_label)
                    
                    card_layout.addWidget(user_container)
            
            cards_layout.addWidget(card)
        
        # 添加弹簧使卡片顶部对齐
        cards_layout.addStretch()
        
        scroll_area.setWidget(cards_container)
        left_layout.addWidget(scroll_area)
        
        # 右侧：添加功能区域
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(10, 0, 10, 0)
        right_layout.setSpacing(20)
        
        # 添加好友部分
        add_friend_label = QLabel("添加好友")
        add_friend_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                padding: 10px;
            }
        """)
        right_layout.addWidget(add_friend_label)
        
        friend_username = QLineEdit()
        friend_username.setPlaceholderText("输入对方用户名")
        friend_username.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                font-size: 14px;
                border-radius: 5px;
            }
        """)
        right_layout.addWidget(friend_username)

        friend_req = QLineEdit()
        friend_req.setPlaceholderText("输入您的自我介绍")
        friend_req.setStyleSheet(friend_username.styleSheet())
        right_layout.addWidget(friend_req)
        
        send_friend_btn = PillButton("发送好友申请")
        right_layout.addWidget(send_friend_btn)
        send_friend_btn.clicked.connect(lambda:self.adduser(friend_username.text(),friend_req.text()))
        
        # 添加分隔线
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setStyleSheet("color: #555;")
        right_layout.addWidget(line)
        
        # 添加聊天室部分
        add_room_label = QLabel("添加聊天室")
        add_room_label.setStyleSheet(add_friend_label.styleSheet())
        right_layout.addWidget(add_room_label)
        
        room_number = QLineEdit()
        room_number.setPlaceholderText("输入聊天室房号")
        room_number.setStyleSheet(friend_username.styleSheet())
        right_layout.addWidget(room_number)

        room_req = QLineEdit()
        room_req.setPlaceholderText("输入您的进群介绍")
        room_req.setStyleSheet(friend_username.styleSheet())
        right_layout.addWidget(room_req)
        
        send_room_btn = PillButton("申请加入聊天室")
        right_layout.addWidget(send_room_btn)
        send_room_btn.clicked.connect(lambda:self.addroom(room_number.text(),room_req.text()))
        
        # 添加分隔线
        line2 = QFrame()
        line2.setFrameShape(QFrame.HLine)
        line2.setFrameShadow(QFrame.Sunken)
        line2.setStyleSheet("color: #555;")
        right_layout.addWidget(line2)
        
        # 创建聊天室部分
        create_room_label = QLabel("创建聊天室")
        create_room_label.setStyleSheet(add_friend_label.styleSheet())
        right_layout.addWidget(create_room_label)
        
        room_id = QLineEdit()
        room_id.setPlaceholderText("输入房号")
        room_id.setStyleSheet(friend_username.styleSheet())
        right_layout.addWidget(room_id)
        
        room_name = QLineEdit()
        room_name.setPlaceholderText("输入群名称")
        room_name.setStyleSheet(friend_username.styleSheet())
        right_layout.addWidget(room_name)
        
        invite_users = QLineEdit()
        invite_users.setPlaceholderText("输入要邀请的用户名(多个用空格分隔)")
        invite_users.setStyleSheet(friend_username.styleSheet())
        right_layout.addWidget(invite_users)

        croom_req = QLineEdit()
        croom_req.setPlaceholderText("输入您的群聊介绍")
        croom_req.setStyleSheet(friend_username.styleSheet())
        right_layout.addWidget(croom_req)
        
        create_room_btn = PillButton("创建聊天室")
        right_layout.addWidget(create_room_btn)
        create_room_btn.clicked.connect(lambda:self.croom(room_id.text(),room_name.text(),invite_users.text(),croom_req.text()))
        
        # 添加弹簧使内容顶部对齐
        right_layout.addStretch()
        
        # 将左右两部分添加到主布局
        main_layout.addWidget(left_widget)
        main_layout.addWidget(right_widget)
        self.center()
        
        add_window.show()
        
      except Exception as e:
        print(f"打开添加窗口错误: {e}")
        QMessageBox.critical(self, '错误', f'打开添加窗口失败: {str(e)}')

    def adduser(self,text,fr):
      try:
        n = ast.literal_eval(decrypt(r('getname/'+str([text]))))[0]
        reply = QMessageBox.question(
            self, '确认添加', 
            f"是否确认申请添加{text}，对方名称：{n if n != '' else '【不存在的用户！】'}",
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
          data={
            "username":encrypt(username),
            "password":encrypt(password),
            "friendUsername":encrypt(text),
            "introduction":encrypt(fr)}
          rr = json.loads(decrypt(p("adduser",data)))
          QMessageBox.information(self, '添加好友', rr["result"])
      except Exception as e:
        print(e)

    def addroom(self,a,b):
      try:
        a="#"+a.replace("#","")
        n = decrypt(p('getroomname',{"roomnum":encrypt(a)}))
        reply = QMessageBox.question(
            self, '确认添加', 
            f"是否确认申请添加Room{a}，群聊名称：{n}",
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
          data={
            "username":encrypt(username),
            "password":encrypt(password),
            "roomnum":encrypt(a),
            "introduction":encrypt(b)}
          rr = json.loads(decrypt(p("addroom",data)))
          QMessageBox.information(self, '添加聊天室', rr["result"])
      except Exception as e:
        print("ar",e)

    def croom(self,rid,rname,iu,req):
      try:
        rid="#"+rid.replace("#","")
        reply = QMessageBox.question(
            self, '确认创建', 
            f"是否确认创建Room{rid}，群聊名称：{rname}",
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
          data={
            "username":encrypt(username),
            "password":encrypt(password),
            "roomnum":encrypt(rid),
            "roomname":encrypt(rname),
            "introduction":encrypt(req),
            "users":encrypt(iu)}
          rr = json.loads(decrypt(p("createroom",data)))
          QMessageBox.information(self, '创建聊天室', rr["result"])
      except Exception as e:
        print("ar",e)

    def handle_request(self, card, user_container, is_accept):
        try:
            """处理接受/拒绝请求"""
            title = card.title  # 获取卡片标题
            user = user_container.user  # 获取用户名
    
            action = "接受" if is_accept else "拒绝"
            print(f"{action}请求 - 卡片标题: {title}, 用户名: {user}")
            
            if title == "好友":
                data = {
                    "username": encrypt(username),
                    "password": encrypt(password),
                    "user": encrypt(user)
                }
                print(data)
                if is_accept:
                    rr=json.loads(decrypt(p("adduserconfirm",data)))["result"]
                else:
                    rr=json.loads(decrypt(p("adduserrefuse",data)))["result"]
            elif title == "群聊邀请":
                data = {
                    "username": encrypt(username),
                    "password": encrypt(password),
                    "roomnum": encrypt(user),
                    "action":encrypt("agree"if is_accept else "deny")
                }
                print(data)
                rr=json.loads(decrypt(p("roominvite",data)))["result"]
            else:
                data = {
                    "username": encrypt(username),
                    "password": encrypt(password),
                    "roomnum": encrypt(title),
                    "waitinguser":encrypt(user)
                }
                print(data)
                if is_accept:
                    rr=json.loads(decrypt(p("addroomconfirm",data)))["result"]
                else:
                    rr=json.loads(decrypt(p("addroomrefuse",data)))["result"]
            
            # 显示操作结果
            QMessageBox.information(self, "操作结果", rr)
        except Exception as e:
            print("44",e)


    def open_user_window(self):
      try:
        global version
        """个人中心UI 人工实操练习"""
        self.user_window = QMainWindow(self)
        self.user_window.setWindowTitle("Lanmei Chat - 个人中心")
        self.user_window.resize(800, 800)
        self.center()

        cw = QWidget()
        self.user_window.setCentralWidget(cw)#中央容器

        ml = QVBoxLayout()
        cw.setLayout(ml)#主布局采用垂直布局
        ml.setAlignment(Qt.AlignCenter)
        ml.setContentsMargins(15,15,15,15)

        self.pp = QPushButton(logindata.get("name","未知用户")[0])
        self.pp.setFixedSize(90,90)
        self.pp.setStyleSheet("background-color: #103667; border-radius: 45px; border: none; font-size:40px; color:white;")
        ml.addWidget(self.pp, alignment=Qt.AlignCenter)

        n = QLabel(username)
        n.setStyleSheet("font-size:30px;margin-top:10px;margin-bottom:10px;")
        n.setAlignment(Qt.AlignCenter)
        ml.addWidget(n)

        nhc = QWidget()
        nh = QHBoxLayout(nhc)
        nh.setContentsMargins(0,0,0,0)
        ne = QLineEdit()
        ne.addAction(qta.icon("mdi.account-edit",color="white"),QLineEdit.LeadingPosition)
        ne.setStyleSheet("")
        ne.setPlaceholderText("名称")
        ne.setText(logindata.get("name","未知用户"))
        ne.setStyleSheet("""
          QLineEdit {
            font-size: 14px;
            border: 2px solid #000000;
            border-radius: 25px;
            min-height: 50px;
            margin: 0 0;
          }
        """)
        nh.addWidget(ne)
        accept_btn = QPushButton()
        accept_btn.setFixedSize(50, 50)
        accept_btn.setIcon(qta.icon("fa5s.check", color="white"))
        accept_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #4CAF50;
                            border-radius: 25px;
                            border: none;
                        }
                        QPushButton:hover {
                            background-color: #66BB6A;
                        }
        """)
        nh.addWidget(accept_btn)
        ml.addWidget(nhc)
        accept_btn.clicked.connect(lambda:self.changename(ne.text()))

        pwc = QWidget()
        pw = QHBoxLayout(pwc)
        pw.setContentsMargins(0,0,0,0)
        self.pwl = QLineEdit()
        self.pwl.addAction(qta.icon("mdi.lock",color="white"),QLineEdit.LeadingPosition)
        self.pwl.setStyleSheet("")
        self.pwl.setEchoMode(QLineEdit.Password)
        self.pwl.setPlaceholderText("修改密码（请先在此输入原密码）")
        self.pwl.setStyleSheet("""
          QLineEdit {
            font-size: 14px;
            border: 2px solid #000000;
            border-radius: 25px;
            min-height: 50px;
            margin: 0 0;
          }
        """)###@@
        pw.addWidget(self.pwl)
        ac = QPushButton()
        ac.setFixedSize(50, 50)
        ac.setIcon(qta.icon("fa5s.check", color="white"))
        ac.setStyleSheet("""
                        QPushButton {
                            background-color: #4CAF50;
                            border-radius: 25px;
                            border: none;
                        }
                        QPushButton:hover {
                            background-color: #66BB6A;
                        }
        """)
        pw.addWidget(ac)
        ml.addWidget(pwc)
        ac.clicked.connect(lambda:self.changepwd(self.pwl.text(),self.pwl.placeholderText()))

        lo = PillButton("退出登录")
        lo.setIcon(qta.icon("mdi.logout", color="white"))
        ml.addWidget(lo)
        lo.clicked.connect(self.confirm_logout)

        off = QPushButton("删除账户")
        off.setIcon(qta.icon("mdi.account-remove", color="white"))
        off.setStyleSheet("""
            QPushButton {
                border: none;
                border-radius: 20px;
                padding: 0px;
                margin: 0px;
                font-size: 14px;
                background-color: #F44336;  /* Material Red 500 */
                color: white;
                min-height: 50px;
            }
            QPushButton:hover {
                background-color: #EF5350;  /* Material Red 400 (更亮) */
            }
            QPushButton:pressed {
                background-color: #D32F2F;  /* Material Red 700 (更暗) */
            }
        """)
        ml.addWidget(off)
        off.clicked.connect(self.logoff)

        gw = PillButton("官网：lanmei.chat")
        gw.setIcon(qta.icon("mdi.web", color="white"))
        ml.addWidget(gw)
        gw.clicked.connect(self.opengw)

        pj = PillButton("评价一下？我们会展示所有真实评价")
        pj.setIcon(qta.icon("mdi.comment", color="white"))
        ml.addWidget(pj)
        pj.clicked.connect(self.openpj)

        a = QLabel("关于我们"+version)
        a.setStyleSheet("font-size:20px;margin-top:10px;margin-bottom:10px;")
        a.setAlignment(Qt.AlignCenter)
        ml.addWidget(a)
        b = QLabel("蓝莓通讯由三位初中生开发，目标在于制作一个纯粹的聊天软件，并培养相关技能与实践能力（顺便当一把产品经理）。我们的程序肯定有诸多不完善之处，还请您多多指教！邀您共同见证蓝莓通讯的成长！")
        b.setStyleSheet("font-size:15px;")
        b.setAlignment(Qt.AlignCenter)
        b.setFixedWidth(800)
        b.setMinimumHeight(40)
        b.setWordWrap(True)
        ml.addWidget(b)
        
        c = QLabel("健康使用忠告")
        c.setStyleSheet("font-size:20px;margin-top:10px;margin-bottom:10px;")
        c.setAlignment(Qt.AlignCenter)
        ml.addWidget(c)
        d = QLabel("社交软件所带来的互动是非即时性（虽然叫即时通讯软件）以及非具身性的。对于一个孩子来说，无法培养您所必须的社交技能及情绪控制能力。此外，社交软件虽然可以让您结识更多的朋友，但远不如现实中紧密。如果您感到焦虑/空虚，请多结交些现实中的朋友，到户外玩会，我们不希望您的“所有朋友都在网络上”。另外，请勿过分相信陌生群友，免得遭遇诈骗哦！如果发现可疑迹象请及时告诉父母/反馈！共勉！")
        d.setStyleSheet("font-size:15px;")
        d.setAlignment(Qt.AlignCenter)
        d.setFixedWidth(800)
        d.setMinimumHeight(60)
        d.setWordWrap(True)
        ml.addWidget(d)
        
        self.user_window.show()
      except Exception as e:
            print("45",e)
    
    newpwd=""
    def changepwd(self,text,ph):
     try:
      global newpwd,password
      if ph == "修改密码（请先在此输入原密码）":
        if text == password:
            self.pwl.setPlaceholderText("请输入新密码")
            self.pwl.setText("")
        else:
            QMessageBox.critical(self, 'Lanmei Chat 蓝莓通讯', "原密码错误！")
      elif ph == "请输入新密码":
          newpwd = text
          self.pwl.setPlaceholderText("请确认新密码")
          self.pwl.setText("")
      else:
       if newpwd == text:
        data={
            "username":encrypt(username),
            "password":encrypt(password),
            "newpwd":encrypt(text)}
        rr = json.loads(decrypt(p("changepwd",data)))
        QMessageBox.information(self, 'Lanmei Chat 蓝莓通讯', rr["result"])
        if rr["result"] == "您已成功修改密码！所有设备都需要重新登录！":
            self.pwl.setPlaceholderText("修改密码（请先在此输入原密码）")
            self.pwl.setText("")
            password = text
       else:
           QMessageBox.information(self, 'Lanmei Chat 蓝莓通讯', "请确保两次输入密码一致！")
     except Exception as e:
            print("45",e)

    def logoff(self):
      try:
        text, ok = QInputDialog.getText(
            self,                      # 父窗口（None 表示无父窗口）
            "确认密码",                # 窗口标题
            ("感谢您使用蓝莓通讯，这是最后一次确认。\n"
             "在下方输入框输入您的密码，然后点击“OK”\n"
             "以永久地删除您的账户及所有数据。您的数据\n"
             "将会在本地清除，为避免恶意操作，服务端将\n"
             "保留您的用户名、密码（经不可逆加密）、群\n"
             "聊信息一段时间。您已发送的消息无法删除。\n"
             "如您为群聊群主，则群主会顺延至下一位用户。\n"
             "好聚好散 ，再见！"),             # 提示文本
            QLineEdit.Password,
            ""
            )
    
        if ok and text:  # 如果用户点击 OK 并且输入不为空
            data={
                "username":encrypt(username),
                "password":encrypt(text)}
            rr = json.loads(decrypt(p("logoff",data)))["result"]
            if rr == "success":
                target_dir = f"Message {username}/"
                try:
                    shutil.rmtree(target_dir)
                    print(f"目录 {target_dir} 已删除")
                except FileNotFoundError:
                    print(f"目录 {target_dir} 不存在")
                except PermissionError:
                    print(f"权限不足，无法删除 {target_dir}")
                except Exception as e:
                    print(f"删除失败: {e}")
                os.remove("key.txt")
                os.remove("config.txt")
                QMessageBox.information(self, 'Lanmei Chat 蓝莓通讯', "再见！")
                app.exec_()
                os._exit(1)
            else:
                QMessageBox.information(self, 'Lanmei Chat 蓝莓通讯', rr)
        else:
            QMessageBox.information(self, 'Lanmei Chat 蓝莓通讯', rr)
      except Exception as e:
            print("77",e)

    def opengw(self):
        url = "https://lanmei.chat"
        webbrowser.open(url,new=2)

    def openpj(self):
        url = "https://lanmei.chat/issue"
        webbrowser.open(url,new=2)


    def changename(self,a):
      try:
        data={
            "username":encrypt(username),
            "password":encrypt(password),
            "newname":encrypt(a)}
        rr = json.loads(decrypt(p("changename",data)))
        QMessageBox.information(self, 'Lanmei Chat 蓝莓通讯', rr["result"])
        if rr["result"] == "您已成功修改名称！":
            self.pp.setText(a[0])
      except Exception as e:
            print("46",e)

    def confirm_logout(self):
        """确认退出登录"""
        global logindata
        reply = QMessageBox.question(
            self, '确认退出', 
            "是否确认退出登录？聊天记录会保留。",
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            logindata = {}
            config.pop("username")
            config.pop("password")
            self.user_window.close()
            configsave()
            #QMessageBox.information(self, 'Lanmei Chat 蓝莓通讯', '已退出登录！')
            try:
                self.stop_thread = True
                self.stop_login = True
                self.message_thread.join()
                self.login_thread.join()
            except:
                pass
            self.initUI()

    def populate_list_data(self):
      try:
        self.list_model.clearAllItems()
        for i in range(len(logindata["userchatlist"])):
            sub = logindata["recent_message"][logindata["userchatlist"][i]]
            if sub != get_last_line(logindata["userchatlist"][i]):
                sub = "[新消息] "+sub
            self.list_model.addItem(logindata["roomnamelist"][i]+' '+logindata["userchatlist"][i], sub)
      except Exception as e:
        print(f"填充列表数据错误: {e}")

    def on_list_selection_changed(self, selected, deselected):
      """处理列表项选择变化"""
      try:
        if not selected.indexes():  # 如果没有选中项
            self.chat_area.show_welcome()  # 显示欢迎标签
            self.setWindowTitle('Lanmei Chat 蓝莓通讯')  # 重置窗口标题
            return
        
        index = selected.indexes()[0]
        if not index.isValid():  # 检查索引是否有效
            self.chat_area.show_welcome()
            return
        
        # 确保有足够的数据
        if not hasattr(self, 'list_model') or not logindata.get("userchatlist") or not logindata.get("roomnamelist"):
            self.chat_area.show_welcome()
            return
        
        # 检查索引是否在有效范围内
        if index.row() >= len(logindata["userchatlist"]):
            self.chat_area.show_welcome()
            return
        
        self.room_id = logindata["userchatlist"][index.row()]
        self.room_name = logindata["roomnamelist"][index.row()]
        
        # 显示聊天区域
        self.chat_area.show_chat()
        self.load_chat_messages(self.room_id, self.room_name)
    
      except Exception as e:
        print(f"处理列表选择变化时出错: {e}")
        self.chat_area.show_welcome()

    def send_message(self):
      try:
       text = self.chat_area.input_field.text().strip()

       # 移除用户输入中的换行符（可选）
       text = text.replace('\n', ' ').replace('\r', ' ')
       if text and "【文件】" not in text:
        t = time.strftime('%Y-%m-%d %H:%M:%S')
        data = {
            "username": encrypt(username),
            "password": encrypt(password),
            "roomnum": encrypt(self.room_id),
            "message": encrypt(f"{username}：{text}【{t}】")
        }
        r = json.loads(decrypt(p("sendmessage", data)))
        
        if r['result'] == 'success':
            self.chat_area.add_message(f"{username}：{text}【{t}】", is_left=False)
            self.chat_area.input_field.clear()
            # 确保消息格式干净无换行
            save_message(
                self.room_id,
                f"{username}：{text}【{t}】"
            )
        else:
            QMessageBox.critical(self, '发送失败', r['result'])
       else:
           QMessageBox.critical(self, '发送失败', f'不能发空消息！消息中不能包含【文件】！')
      except Exception as e:
        print('发送失败:', e)
        QMessageBox.critical(self, '发送失败', f'错误：{str(e)}')

    def send_file(self):  # FTP文件上传
      try:
        # 1. 选择文件
        file_path, _ = QFileDialog.getOpenFileName(
            None, 
            "选择文件", 
            "", 
            "所有文件 (*.*)"
        )
        
        if not file_path:  # 用户取消了选择
            return
            
        print("选择的文件路径:", file_path)
        remote_filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # 2. 连接FTP服务器
        ftp = FTP()
        ftp.connect(host=ftp_server, port=ftp_port, timeout=30)  # 增加超时
        ftp.login(user=ftp_username, passwd=ftp_password)
        ftp.set_pasv(True)  # 启用被动模式
        
        print("FTP连接成功!")
        ftp.cwd("/lanmeichat")
        print("当前目录:", ftp.pwd())
        
        # 3. 处理目标目录
        TARGET_DIR = "/lanmeichat/" + rid.replace("#", "")
        
        try:
            ftp.cwd(TARGET_DIR)
            print(f"目录 {TARGET_DIR} 已存在")
        except error_perm as e:
            if "550" in str(e):
                print(f"目录 {TARGET_DIR} 不存在，尝试创建...")
                try:
                    ftp.mkd(TARGET_DIR)
                    print(f"目录 {TARGET_DIR} 创建成功!")
                    ftp.cwd(TARGET_DIR)
                except error_perm as e:
                    QMessageBox.critical(self, '错误', f'无法创建目录: {str(e)}')
                    print(str(e))
                    return
            else:
                QMessageBox.critical(self, '错误', f'目录访问错误: {str(e)}')
                return

        # 4. 设置进度条
        progress = QProgressDialog("文件上传中...", "取消", 0, 100, self)
        progress.setWindowTitle("上传进度")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        progress.setValue(0)
        
        # 5. 计算本地文件MD5（用于校验）
        def calculate_md5(filepath):
            hash_md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        
        local_md5 = calculate_md5(file_path)
        print(f"本地文件MD5: {local_md5}")

        # 6. 断点续传逻辑
        try:
            remote_size = ftp.size(remote_filename)  # 获取远程文件大小
        except error_perm:
            remote_size = 0

        if 0 < remote_size < file_size:  # 部分已上传
            resume = QMessageBox.question(
                self, 
                "续传确认", 
                f"发现未完成的上传(已传{remote_size/1024:.1f}KB)，是否继续?",
                QMessageBox.Yes | QMessageBox.No
            )
            if resume == QMessageBox.No:
                remote_size = 0

        # 7. 上传文件（带进度回调）
        uploaded_bytes = remote_size
        last_progress = 0

        def upload_callback(data):
            nonlocal uploaded_bytes, last_progress
            uploaded_bytes += len(data)
            current_progress = int((uploaded_bytes / file_size) * 100)
            if current_progress > last_progress:  # 减少UI更新频率
                progress.setValue(current_progress)
                last_progress = current_progress
                QApplication.processEvents()
            
            if progress.wasCanceled():
                raise Exception("用户取消上传")

        try:
            with open(file_path, 'rb') as f:
                if remote_size > 0:
                    f.seek(remote_size)
                    ftp.voidcmd('TYPE I')  # 确保二进制模式
                    ftp.storbinary(
                        f'APPE {remote_filename}', 
                        f, 
                        blocksize=8192, 
                        callback=upload_callback
                    )
                    action = "续传"
                else:
                    ftp.storbinary(
                        f'STOR {remote_filename}', 
                        f, 
                        blocksize=8192, 
                        callback=upload_callback
                    )
                    action = "上传"
            
            # 8. 校验文件完整性
            if not progress.wasCanceled():
                progress.setLabelText("校验文件中...")
                QApplication.processEvents()
                
                # 简单校验文件大小
                remote_size_after = ftp.size(remote_filename)
                if remote_size_after == file_size:
                    QMessageBox.information(
                        self, 
                        '成功', 
                        f'文件{action}成功!\n大小: {file_size/1024:.1f}KB'
                    )
                else:
                    QMessageBox.warning(
                        self, 
                        '警告', 
                        f'文件{action}不完整\n(本地:{file_size} 远程:{remote_size_after})'
                    )
        except Exception as e:
            if "用户取消上传" in str(e):
                QMessageBox.information(self, "提示", "上传已取消")
            else:
                QMessageBox.critical(self, '上传失败', f'文件上传失败: {str(e)}')
                
        # 9.发送消息
        text = "【文件】"+remote_filename
        t = time.strftime('%Y-%m-%d %H:%M:%S')
        data = {
            "username": encrypt(username),
            "password": encrypt(password),
            "roomnum": encrypt(self.room_id),
            "message": encrypt(f"{username}：{text}【{t}】")
        }
        r = json.loads(decrypt(p("sendmessage", data)))
        
        if r['result'] == 'success':
            self.chat_area.add_message(f"{username}：{text}【{t}】", is_left=False)
            self.chat_area.input_field.clear()
            # 确保消息格式干净无换行
            save_message(
                self.room_id,
                f"{username}：{text}【{t}】"
            )
        else:
            QMessageBox.critical(self, '发送文件失败', r['result'])
      except Exception as e:
        print('发送文件失败:', e)
        QMessageBox.critical(self, '错误', f'连接失败: {str(e)}')
      finally:
        if 'ftp' in locals() and ftp.sock is not None:
            ftp.quit()
            print("FTP连接已关闭")
        if 'progress' in locals():
            progress.close()

    def load_chat_messages(self, room_id, room_name):
      global username, password,rid
      rid = room_id
      print(username)
      """加载指定聊天室的聊天记录"""

      # 停止之前的线程（如果存在）
      if hasattr(self, 'message_thread') and self.message_thread.is_alive():
          self.stop_thread = True
          self.message_thread.join()
          print("停止接收")
          
      # 清除当前聊天区域
      self.chat_area.clear_messages()
    
      # 设置窗口标题显示当前聊天室
      self.setWindowTitle(f'Lanmei Chat - {room_name} {room_id}')
    
      try:
        # 加载本地消息
        for line in get_local_message(room_id).split('\n'):
            if line.strip():
                try:
                    sender = line.split("：", 1)[0]
                    self.chat_area.add_message(line, sender != username)
                except IndexError:
                    # 处理格式错误的消息
                    self.chat_area.add_message(line, True)
        
        # 获取服务器消息
        data = {
            "username": encrypt(username),
            "password": encrypt(password),
            "roomnum": encrypt(room_id),
            "message": encrypt(get_last_line(room_id))
        }
        r = decrypt(p("getmessage", data))
        print(r)
        # 添加欢迎消息
        welcome_msg = f"**系统**：欢迎进入聊天室: {room_name} {room_id}，您已连接成功。（此为欢迎消息，别人无法看见）【{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}】"
        self.chat_area.add_message(welcome_msg, is_left=True)
        
        # 处理服务器返回的消息
        for line in r.split('\n'):
            if line.strip():
                if "【**RECALL**】》" not in line:
                    try:
                      if line not in get_local_message(room_id):
                        sender = line.split("：", 1)[0]
                        self.chat_area.new_message_signal.emit(line, sender != username)
                        print("渲染"+line)
                      else:
                          print("此行已渲染")
                    except IndexError:
                        self.chat_area.add_message(line, True)
                else:
                    # 处理撤回消息部分
                    try:
                        message = line.split("【**RECALL**】》")[1].split("《【**RECALL**】")[0]
                        # 修改气泡内容
                        if not self.chat_area.modify_bubble(message, "【已撤回的内容】"):
                             print(f"未找到匹配的消息气泡: {message}")
                        r=r.replace(line,"")
                        # 从右侧找到最后一个【和】
                        last_left_bracket = message.rfind("【")
                        last_right_bracket = message.rfind("】")
        
                        #if last_left_bracket < last_right_bracket:  # 确保【在】左侧
                        t = message[last_left_bracket+1 : last_right_bracket]
                        print(message[last_left_bracket+1 : last_right_bracket])
                        r=r.replace(message,f"{sender}：【"+t+"】")
                        print('OK')
                        # 更新本地文件
                        with open(f"Message {username}/Room{room_id}.txt", "r+", encoding='utf-8') as f:
                            content = f.read()
                            f.seek(0)
                            f.write(content.replace(message,f"{sender}：【"+t+"】"))
                            f.truncate()
                    except Exception as e:
                        print(f"处理撤回消息时出错（第一次报文件不存在请忽略）: {e}")
        if not self.is_invisible(r):
            # 保存新消息到本地
            save_message(room_id, r)
            print("已保存")

        # 初始获取消息
        self.stop_thread = False
        self.message_thread = threading.Thread(target=self.getmess, args=(room_id, room_name))
        self.message_thread.daemon = True
        self.message_thread.start()
        
        # 所有消息渲染完成后强制滚动到底部
        QTimer.singleShot(200, lambda: self.chat_area.scroll_area.verticalScrollBar().setValue(
            self.chat_area.scroll_area.verticalScrollBar().maximum()
        ))
      except Exception as e:
        print(f"加载聊天记录错误: {e}")
        QMessageBox.critical(self, '错误', f'加载聊天记录失败: {str(e)}')

    def getmess(self, room_id, room_name):
      try:
       while not self.stop_thread:
        for _ in range(50):  # 分成50次检查，每0.1秒检查一次，以便更快响应停止信号
            if self.stop_thread:
                return
            time.sleep(0.1)
        print("接收一次")
        # 获取服务器消息
        data = {
            "username": encrypt(username),
            "password": encrypt(password),
            "roomnum": encrypt(room_id),
            "message": encrypt(get_last_line(room_id))
        }
        r = decrypt(p("getmessage", data))
        print(r)
        # 处理服务器返回的消息
        for line in r.split('\n'):
            if line.strip():
                if "【**RECALL**】》" not in line:
                    try:
                      if line not in get_local_message(room_id):
                        sender = line.split("：", 1)[0]
                        self.chat_area.new_message_signal.emit(line, sender != username)
                        print("渲染（2）"+line)
                      else:
                          print("此行已渲染")
                    except IndexError:
                        self.chat_area.new_message_signal.emit(line, True)
                else:
                    # 处理撤回消息部分
                    try:
                        message = line.split("【**RECALL**】》")[1].split("《【**RECALL**】")[0]
                        self.chat_area.resignal.emit(message)
                        print("发了撤回信号",message)
                        r=r.replace(line,"")
                        # 从右侧找到最后一个【和】
                        last_left_bracket = message.rfind("【")
                        last_right_bracket = message.rfind("】")
        
                        #if last_left_bracket < last_right_bracket:  # 确保【在】左侧
                        t = message[last_left_bracket+1 : last_right_bracket]
                        print(message[last_left_bracket+1 : last_right_bracket])
                        r=r.replace(message,f"{sender}：【"+t+"】")
                        print('OK')
                        # 更新本地文件
                        with open(f"Message {username}/Room{room_id}.txt", "r+", encoding='utf-8') as f:
                            content = f.read()
                            f.seek(0)
                            f.write(content.replace(message,f"{sender}：【"+t+"】"))
                            f.truncate()
                    except Exception as e:
                        print(f"处理撤回消息时出错（第一次报文件不存在请忽略）: {e}")
        if not self.is_invisible(r):
          # 保存新消息到本地
          save_message(room_id, r)
          print("已保存")
 
      except Exception as e:
        print(f"加载聊天记录错误: {e}")
        QMessageBox.critical(self, '错误', f'加载聊天记录失败: {str(e)}')

    def closeEvent(self, event):
        """窗口关闭时停止消息线程"""
        if hasattr(self, 'message_thread') and self.message_thread.is_alive():
            self.stop_thread = True
            self.stop_login = True
            self.message_thread.join()
            self.login_thread.join()
            os._exit(1)
        event.accept()

    def is_invisible(self,s):
        return all(c.isspace() or not c.isprintable() for c in s)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # 应用Material Design样式
    apply_stylesheet(app, theme='dark_purple.xml')
    
    ex = MaterialApp()
    ex.show()
    sys.exit(app.exec_())

#哈哈终于写完了，马上打包了。8月1日摸鱼和蓝莓去陆家嘴的易拉罐苹果店，演示机不让安装python环境（要密码），MacOS客户端还要等待一会（）
#学习一下我们的竞争对手微信（说这话我自己都想笑）fuckMACOS
