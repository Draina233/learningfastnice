from fastapi import FastAPI
from nicegui import ui
import base64
import json

from nicegui.tailwind_types import content

from nicegui import app

# 添加静态文件目录（通常默认已配置）
app.add_static_files('/static', 'static')

# 创建FastAPI应用
fastapi_app = FastAPI()

# 样式定义
SIDEBAR_STYLE = """
position: fixed;
left: 0;
top: 0;
bottom: 0;
width: 250px;
background: #ffffff;
box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1);
z-index: 1000;
"""

CONTENT_STYLE = """
margin-left: 250px; 
padding: 20px;
"""


# 侧边栏管理器
class SidebarManager:
    def create_sidebar(self, content_container):
        with ui.column().style(SIDEBAR_STYLE).classes("p-2 gap-2") as sidebar:
            # 导航标题
            ui.label("导航栏").classes("font-bold")

            # 导航项
            nav_items = [
                ("/", "首页", "home"),
                ("/converter", "编码转换", "swap_horiz"),
                ("/score", "密评计算", "calculate")
            ]

            # 创建导航按钮
            for route, text, icon in nav_items:
                with ui.button(icon=icon).props("flat").classes("w-full justify-start") as nav_btn:
                    ui.label(text)
                    nav_btn.on_click(lambda _, r=route: ui.navigate.to(r))

        return sidebar


# 初始化侧边栏管理器
sidebar_manager = SidebarManager()


# 首页
@ui.page('/')
def home_page():
    with ui.row().classes("w-full h-screen") as page_container:
        # 内容区域
        with ui.column().style(CONTENT_STYLE).classes("w-full h-full"):
            ui.page_title("欢迎使用Draina的工具箱")

            with ui.column().classes("max-w-7xl mx-auto p-6 w-full h-full gap-4"):
                # 标题区
                ui.label("欢迎使用Draina的工具箱🔧").classes("text-2xl font-bold text-center text-gray-800 mb-2")
                ui.separator().classes("mb-6")

                # 主内容区
                with ui.row().classes("w-full gap-6"):
                    # 左侧主内容
                    with ui.column().classes("flex-1 space-y-6"):
                        # 欢迎卡片
                        with ui.card().classes("w-full p-6 shadow-lg rounded-xl bg-blue-50"):
                            ui.markdown('''
                                ## 🚀 工具箱特色
                                ✨ ​**持续更新** - 边学边构建，保持功能迭代  
                                🛠️ ​**实用工具** - 聚焦开发实用功能  
                                🧩 ​**模块设计** - 功能相互独立，按需使用  
                                🎉 ​**来访人次** 
                                ![learntoolweb](https://count.getloli.com/@learntoolweb?name=learntoolweb&theme=booru-lewd&padding=7&offset=0&align=top&scale=1&pixelated=1&darkmode=auto)
                            ''').classes("text-lg text-gray-700")

                            ui.separator().classes("my-4")

                            with ui.grid(columns=2).classes("w-full gap-4"):
                                with ui.card().classes("p-4 bg-orange-50 rounded-lg shadow"):
                                    ui.label("📢 最新公告").classes("font-bold text-orange-800")
                                    ui.markdown('''
                                        ​**2024.03.20**   
                                        - 新增编码转换工具  
                                        - 优化移动端显示
                                    ''')
                                with ui.card().classes("p-4 bg-white rounded-lg shadow"):
                                    ui.label("🛠️ 开发中功能").classes("font-bold text-blue-600")
                                    ui.markdown('''
                                        - 密评分数计算器  
                                        - 证书链验证
                                        - 抓包文件分析
                                    ''')

                    # 右侧侧边区
                    with ui.column().classes("w-80 space-y-6"):


                        # 开发者信息
                        with ui.card().classes("p-4 shadow-lg rounded-xl bg-purple-50"):
                            ui.label("💻 开发者信息").classes("text-xl font-bold text-purple-800 mb-3")
                            with ui.row().classes("items-center gap-4"):
                                ui.image("/static/avatar.jpg").classes("rounded-full")
                                with ui.column():
                                    ui.label("Draina").classes("font-bold text-3xl")
                                    ui.markdown("密评工程师 | 编程爱好者 | FPS苦手").classes("text-sm text-gray-600")
                            ui.separator().classes("my-3")
                            with ui.column().classes("space-y-1 text-sm"):
                                ui.html('''
                                        <div class="flex flex-col gap-1">
                                            <div class="flex items-center">
                                                <span class="w-[32px]">🐈</span>
                                                <span class="w-16 font-medium pr-2">GitHub:</span>
                                                <a href="https://github.com/Draina233" target="_blank">Draina233</a>
                                            </div>
                                            <div class="flex items-center">
                                                <span class="w-[32px]">🖊</span>
                                                <span class="w-16 font-medium pr-2">Blogs:</span>
                                                <a href="https://www.cnblogs.com/Draina" target="_blank">Draina</a>
                                            </div>
                                            <div class="flex items-center">
                                                <span class="w-[32px]">📺</span>
                                                <span class="w-16 font-medium pr-2">BiliBili:</span>
                                                <a href="https://space.bilibili.com/290793235" target="_blank">Draina</a>
                                            </div>
                                            <div class="flex items-center">
                                                <span class="w-[32px]">📧</span>
                                                <span class="w-16 font-medium pr-2">邮箱:</span>
                                                <span>draina@qq.com</span>
                                            </div>
                                        </div>
                                    ''')
                # 页脚
                ui.separator().classes("mt-8")
                ui.label("© 2024 Draina's Toolbox | GPL-3.0 license").classes("text-center text-gray-500 text-sm py-2")

        # 创建侧边栏
        sidebar_manager.create_sidebar(content)

# 多格式编码转换
@ui.page('/converter')
def converter_page():
    with ui.row().classes("w-full") as page_container:
        # 内容区域
        with ui.column().style(CONTENT_STYLE).classes("w-full") as content:
            ui.page_title("编码转换工具")

            with ui.column().classes("w-full p-4"):
                ui.label("多格式编码转换工具").classes("text-2xl font-bold mb-4 text-primary")

                # 转换格式选择
                with ui.row().classes("w-full items-center gap-4"):
                    src_format = ui.select(
                        options={'Base64': 'Base64', 'Hex': '十六进制', 'Binary': '二进制', 'UTF-8': 'UTF-8'},
                        label="源格式",
                        value='Base64'
                    ).classes("min-w-[120px]")

                    ui.icon('swap_horiz').classes("mt-4 text-2xl")

                    dst_format = ui.select(
                        options={'Base64': 'Base64', 'Hex': '十六进制', 'Binary': '二进制', 'UTF-8': 'UTF-8'},
                        label="目标格式",
                        value='Hex'
                    ).classes("min-w-[120px]")

                # 输入区域
                with ui.row().classes("w-full items-center"):
                    input_area = ui.textarea(label="输入内容").classes("w-full font-mono text-sm").props("""
                        outlined dense
                        rows=6
                        style="width: 100%"
                    """)

                # 操作按钮
                with ui.row().classes("w-full justify-center gap-4 py-4"):
                    convert_btn = ui.button("开始转换", icon="swap_horiz").props("unelevated")
                    clear_btn = ui.button("清空内容", icon="delete").props("flat")
                    copy_btn = ui.button("复制结果",icon="content_copy").props("flat")

                # 输出区域
                with ui.card().classes("w-full p-4").style("min-height: 200px;"):
                    with ui.row().classes("w-full justify-between items-center"):
                        ui.label("转换结果：").classes("text-lg font-medium")

                    output_area = ui.label().classes("text-sm font-mono break-all w-full")

                # 状态提示
                status = ui.label().classes("text-sm text-gray-500 px-2")

                # 复制功能函数
                def copy_output():
                    text = output_area.text
                    if not text:
                        status.set_text("没有内容可复制")
                        return

                    try:
                        ui.run_javascript(f"navigator.clipboard.writeText({json.dumps(text)})")
                        status.set_text("已复制到剪贴板！")
                    except Exception as e:
                        status.set_text(f"复制失败：{str(e)}")

                # 转换处理函数
                async def convert():
                    try:
                        input_text = input_area.value.strip()
                        input_text_count = len(input_text)
                        if not input_text:
                            status.set_text("请输入要转换的内容")
                            return

                        src = src_format.value
                        dst = dst_format.value

                        bytes_data = await convert_to_bytes(input_text, src)
                        result = await convert_from_bytes(bytes_data, dst)

                        result_bytes = result.encode('utf-8')
                        result_byte_count = len(result_bytes)

                        output_area.set_text(result)
                        status.set_text(f"转换成功！{src}（共 {input_text_count} 字节） → {dst}（共 {result_byte_count} 字节）")

                    except Exception as e:
                        status.set_text(f"错误：{str(e)}")
                        output_area.set_text("")

                async def convert_to_bytes(data: str, fmt: str) -> bytes:
                    """将输入转换为字节数据"""
                    try:
                        if fmt == 'Base64':
                            return base64.b64decode(data)
                        elif fmt == 'Hex':
                            data = data.replace(' ', '')  # 自动去除输入中的空格
                            if len(data) % 2 != 0:
                                raise ValueError("十六进制字符串长度必须为偶数")
                            return bytes.fromhex(data)
                        elif fmt == 'Binary':
                            data = data.replace(' ', '')  # 自动去除输入中的空格
                            if not set(data) <= {'0', '1'}:
                                raise ValueError("二进制字符串包含非法字符")
                            padding = (8 - len(data) % 8) % 8
                            data = data + '0' * padding
                            return int(data, 2).to_bytes(len(data) // 8, 'big')
                        elif fmt == 'UTF-8':
                            return data.encode('utf-8')
                    except Exception as e:
                        raise ValueError(f"输入格式错误（{fmt}）：{str(e)}")

                async def convert_from_bytes(data: bytes, fmt: str) -> str:
                    """将字节数据转换为目标格式（关键修改部分）"""
                    try:
                        if fmt == 'Base64':
                            return base64.b64encode(data).decode('utf-8')
                        elif fmt == 'Hex':
                            return data.hex()  # 修改点：去除空格
                        elif fmt == 'Binary':
                            return ''.join(f"{byte:08b}" for byte in data)  # 修改点：去除空格
                        elif fmt == 'UTF-8':
                            try:
                                return data.decode('utf-8')
                            except UnicodeDecodeError:
                                return data.decode('utf-8', errors='replace')
                    except Exception as e:
                        raise ValueError(f"输出格式转换失败（{fmt}）：{str(e)}")

                def clear():
                    input_area.set_value("")
                    output_area.set_text("")
                    status.set_text("准备就绪")

                convert_btn.on_click(convert)
                clear_btn.on_click(clear)
                copy_btn.on_click(copy_output)
                # 页脚
                ui.separator().classes("mt-8")
                ui.label("© 2024 Draina's Toolbox | GPL-3.0 license").classes("text-center text-gray-500 text-sm py-2")

        # 创建侧边栏
        sidebar_manager.create_sidebar(content)


@ui.page('/score')
def score_page():
    with ui.row().classes("w-full") as page_container:
        # 内容区域
        with ui.column().style(CONTENT_STYLE).classes("w-full") as content:
            ui.page_title("密评分数计算器")

            # 系统等级切换
            with ui.row().classes("mb-4"):
                level_radio = ui.radio(['二级系统', '三级系统'], value='三级系统', on_change=lambda e: update_ui(e.value))

            # 各层分数计算区域
            with ui.card().classes("w-full p-4"):
                # 物理层
                with ui.column().classes("mb-4"):
                    ui.label("物理和环境安全").classes("font-bold mb-2")
                    with ui.row().classes("items-center mb-2"):
                        physical_check1 = ui.checkbox("（宜）身份鉴别")
                        physical_check1.set_value(True)
                        physical_input1 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        physical_check2 = ui.checkbox("（宜）电子门禁记录数据存储完整性")
                        physical_check2.set_value(True)
                        physical_input2 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        physical_check3 = ui.checkbox("（宜）视频记录数据存储完整性")
                        physical_check3.set_value(True)
                        physical_input3 = ui.input().props("type=number").classes("w-24 ml-2")

                # 网络层
                with ui.column().classes("mb-4"):
                    ui.label("网络和通信安全").classes("font-bold mb-2")
                    with ui.row().classes("items-center mb-2"):
                        network_check1 = ui.checkbox("（应）身份鉴别")
                        network_check1.set_value(True)
                        network_input1 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        network_check2 = ui.checkbox("（宜）通信数据完整性")
                        network_check2.set_value(True)
                        network_input2 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        network_check3 = ui.checkbox("（应）通信过程重要数据机密性")
                        network_check3.set_value(True)
                        network_input3 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        network_check4 = ui.checkbox("（宜）网络边界访问控制信息完整性")
                        network_check4.set_value(True)
                        network_input4 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        network_check5 = ui.checkbox("（可）安全接入认证")
                        network_input5 = ui.input().props("type=number").classes("w-24 ml-2")

                # 设备层
                with ui.column().classes("mb-4"):
                    ui.label("设备和计算安全").classes("font-bold mb-2")
                    with ui.row().classes("items-center mb-2"):
                        device_check1 = ui.checkbox("（应）身份鉴别")
                        device_check1.set_value(True)
                        device_input1 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        device_check2 = ui.checkbox("（应）远程管理通道安全")
                        device_check2.set_value(True)
                        device_input2 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        device_check3 = ui.checkbox("（宜）系统资源访问控制信息完整性")
                        device_check3.set_value(True)
                        device_input3 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        device_check4 = ui.checkbox("（宜）重要信息资源安全标记完整性")
                        device_check4.set_value(True)
                        device_input4 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        device_check5 = ui.checkbox("（宜）日志记录完整性")
                        device_check5.set_value(True)
                        device_input5 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        device_check6 = ui.checkbox("（宜）重要可执行程序完整性、重要可执行程序来源真实性")
                        device_check6.set_value(True)
                        device_input6 = ui.input().props("type=number").classes("w-24 ml-2")

                # 应用层
                with ui.column().classes("mb-4"):
                    ui.label("应用和数据安全").classes("font-bold mb-2")
                    with ui.row().classes("items-center mb-2"):
                        app_check1 = ui.checkbox("（应）身份鉴别")
                        app_check1.set_value(True)
                        app_input1 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        app_check2 = ui.checkbox("（宜）访问控制信息完整性")
                        app_check2.set_value(True)
                        app_input2 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        app_check3 = ui.checkbox("（宜）重要信息资源安全标记完整性")
                        app_check3.set_value(True)
                        app_input3 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        app_check4 = ui.checkbox("（应）重要数据传输机密性")
                        app_check4.set_value(True)
                        app_input4 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        app_check5 = ui.checkbox("（应）重要数据存储机密性")
                        app_check5.set_value(True)
                        app_input5 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        app_check6 = ui.checkbox("（宜）重要数据传输完整性")
                        app_check6.set_value(True)
                        app_input6 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        app_check7 = ui.checkbox("（宜）重要数据存储完整性")
                        app_check7.set_value(True)
                        app_input7 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        app_check8 = ui.checkbox("（宜）不可否认性")
                        app_input8 = ui.input().props("type=number").classes("w-24 ml-2")

                # 管理制度
                with ui.column().classes("mb-4"):
                    ui.label("管理制度").classes("font-bold mb-2")
                    with ui.row().classes("items-center mb-2"):
                        manage_check1 = ui.checkbox("（应）具备密码应用安全管理制度")
                        manage_check1.set_value(True)
                        manage_input1 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        manage_check2 = ui.checkbox("（应）密钥管理规则")
                        manage_check2.set_value(True)
                        manage_input2 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        manage_check3 = ui.checkbox("（应）建立操作规程")
                        manage_check3.set_value(True)
                        manage_input3 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        manage_check4 = ui.checkbox("（应）定期修订安全管理制度")
                        manage_check4.set_value(True)
                        manage_input4 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        manage_check5 = ui.checkbox("（应）明确管理制度发布流程")
                        manage_check5.set_value(True)
                        manage_input5 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        manage_check6 = ui.checkbox("（应）制度执行过程记录留存")
                        manage_check6.set_value(True)
                        manage_input6 = ui.input().props("type=number").classes("w-24 ml-2")

                # 人员管理
                with ui.column().classes("mb-4"):
                    ui.label("人员管理").classes("font-bold mb-2")
                    with ui.row().classes("items-center mb-2"):
                        personnel_check1 = ui.checkbox("（应）了解并遵守相关法律制度")
                        personnel_check1.set_value(True)
                        personnel_input1 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        personnel_check2 = ui.checkbox("（应）建立岗位责任制度")
                        personnel_check2.set_value(True)
                        personnel_input2 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        personnel_check3 = ui.checkbox("（应）建立上岗人员培训制度")
                        personnel_check3.set_value(True)
                        personnel_input3 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        personnel_check4 = ui.checkbox("（应）定期进行安全岗位人员考核")
                        personnel_check4.set_value(True)
                        personnel_input4 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        personnel_check5 = ui.checkbox("（应）建立保密制度和调离制度")
                        personnel_check5.set_value(True)
                        personnel_input5 = ui.input().props("type=number").classes("w-24 ml-2")

                # 建设运行
                with ui.column().classes("mb-4"):
                    ui.label("建设运行").classes("font-bold mb-2")
                    with ui.row().classes("items-center mb-2"):
                        construct_check1 = ui.checkbox("（应）制定密码应用方案")
                        construct_check1.set_value(True)
                        construct_input1 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        construct_check2 = ui.checkbox("（应）制定密钥安全管理策略")
                        construct_check2.set_value(True)
                        construct_input2 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        construct_check3 = ui.checkbox("（应）制定实施方案")
                        construct_check3.set_value(True)
                        construct_input3 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        construct_check4 = ui.checkbox("（应）投入运行前进行密评")
                        construct_check4.set_value(True)
                        construct_input4 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        construct_check5 = ui.checkbox("（应）定期密评与攻防演习")
                        construct_check5.set_value(True)
                        construct_input5 = ui.input().props("type=number").classes("w-24 ml-2")

                # 应急处置
                with ui.column().classes("mb-4"):
                    ui.label("应急处置").classes("font-bold mb-2")
                    with ui.row().classes("items-center mb-2"):
                        emergency_check1 = ui.checkbox("（应）应急策略")
                        emergency_check1.set_value(True)
                        emergency_input1 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        emergency_check2 = ui.checkbox("（应）事件处置")
                        emergency_check2.set_value(True)
                        emergency_input2 = ui.input().props("type=number").classes("w-24 ml-2")
                    with ui.row().classes("items-center mb-2"):
                        emergency_check3 = ui.checkbox("（应）向有关部门上报处置情况")
                        emergency_check3.set_value(True)
                        emergency_input3 = ui.input().props("type=number").classes("w-24 ml-2")

            # 计算按钮
            with ui.row().classes("justify-center mb-4"):
                calculate_btn = ui.button("开始计算", on_click=lambda: calculate_score())

            # 结果显示
            with ui.card().classes("w-full p-4"):
                with ui.column().classes("space-y-2"):
                    ui.label("各层得分").classes("font-bold mb-2")
                    physical_result = ui.label("物理层：尚无结果")
                    network_result = ui.label("网络层：尚无结果")
                    device_result = ui.label("设备层：尚无结果")
                    app_result = ui.label("应用层：尚无结果")
                    manage_result = ui.label("管理制度：尚无结果")
                    personnel_result = ui.label("人员管理：尚无结果")
                    construct_result = ui.label("建设运行：尚无结果")
                    emergency_result = ui.label("应急处置：尚无结果")
                    total_result = ui.label("总分：尚无结果")

            # 说明
            ui.label("注意：本工具计算分数仅用于辅助参考，最终分数以实际手动验算结果为准！").classes("text-sm text-gray-500 mt-4")
            ui.label("说明：").classes("text-sm text-gray-500")
            ui.label("1、若显示参数错误，请检查是否勾选了不适用项").classes("text-sm text-gray-500")
            ui.label("2、仔细核实勾选适用项，未勾选的项目不参与计算").classes("text-sm text-gray-500")
            ui.label("3、核实项目安全等级，若为二级系统不要忘记切换").classes("text-sm text-gray-500")
            ui.label("4、本计算工具基于商用密码应用安全性评估量化评估规则（2023版）文件算法具有时效性！").classes("text-sm text-gray-500")

    # 更新UI函数
    def update_ui(level):
        if level == '二级系统':
            # 更新物理层
            physical_check1.set_text("（可）身份鉴别")
            physical_check2.set_text("（可）电子门禁记录数据存储完整性")
            physical_check3.set_text("（无）视频记录数据存储完整性")
            physical_check3.set_value(False)

            # 更新网络层
            network_check1.set_text("（宜）身份鉴别")
            network_check2.set_text("（可）通信数据完整性")
            network_check3.set_text("（宜）通信过程重要数据机密性")
            network_check4.set_text("（可）网络边界访问控制信息完整性")
            network_check5.set_text("（无）安全接入认证")

            # 更新设备层
            device_check1.set_text("（宜）身份鉴别")
            device_check2.set_text("（无）远程管理通道安全")
            device_check2.set_value(False)
            device_check3.set_text("（可）系统资源访问控制信息完整性")
            device_check4.set_text("（无）重要信息资源安全标记完整性")
            device_check4.set_value(False)
            device_check5.set_text("（可）日志记录完整性")
            device_check6.set_text("（无）重要可执行程序完整性、重要可执行程序来源真实性")
            device_check6.set_value(False)

            # 更新应用层
            app_check1.set_text("（宜）身份鉴别")
            app_check2.set_text("（可）访问控制信息完整性")
            app_check3.set_text("（无）重要信息资源安全标记完整性")
            app_check3.set_value(False)
            app_check4.set_text("（宜）重要数据传输机密性")
            app_check5.set_text("（宜）重要数据存储机密性")
            app_check6.set_text("（宜）重要数据传输完整性")
            app_check7.set_text("（宜）重要数据存储完整性")
            app_check8.set_text("（无）不可否认性")
            app_check8.set_value(False)

            # 更新管理制度
            manage_check4.set_text("（无）定期修订安全管理制度")
            manage_check4.set_value(False)
            manage_check5.set_text("（无）明确管理制度发布流程")
            manage_check5.set_value(False)
            manage_check6.set_text("（无）制度执行过程记录留存")
            manage_check6.set_value(False)

            # 更新人员管理
            personnel_check4.set_text("（无）定期进行安全岗位人员考核")
            personnel_check4.set_value(False)

            # 更新建设运行
            construct_check5.set_text("（无）定期密评与攻防演习")
            construct_check5.set_value(False)

            # 更新应急处置
            emergency_check2.set_text("（无）事件处置")
            emergency_check2.set_value(False)
            emergency_check3.set_text("（无）向有关主管部门上报处置情况")
            emergency_check3.set_value(False)
        else:
            # 更新物理层
            physical_check1.set_text("（宜）身份鉴别")
            physical_check2.set_text("（宜）电子门禁记录数据存储完整性")
            physical_check3.set_text("（宜）视频记录数据存储完整性")
            physical_check3.set_value(True)

            # 更新网络层
            network_check1.set_text("（应）身份鉴别")
            network_check2.set_text("（宜）通信数据完整性")
            network_check3.set_text("（应）通信过程重要数据机密性")
            network_check4.set_text("（宜）网络边界访问控制信息完整性")
            network_check5.set_text("（可）安全接入认证")

            # 更新设备层
            device_check1.set_text("（应）身份鉴别")
            device_check2.set_text("（应）远程管理通道安全")
            device_check2.set_value(True)
            device_check3.set_text("（宜）系统资源访问控制信息完整性")
            device_check3.set_value(True)
            device_check4.set_text("（宜）重要信息资源安全标记完整性")
            device_check4.set_value(True)
            device_check5.set_text("（宜）日志记录完整性")
            device_check5.set_value(True)
            device_check6.set_text("（宜）重要可执行程序完整性、重要可执行程序来源真实性")
            device_check6.set_value(True)

            # 更新应用层
            app_check1.set_text("（应）身份鉴别")
            app_check2.set_text("（宜）访问控制信息完整性")
            app_check2.set_value(True)
            app_check3.set_text("（宜）重要信息资源安全标记完整性")
            app_check3.set_value(True)
            app_check4.set_text("（应）重要数据传输机密性")
            app_check4.set_value(True)
            app_check5.set_text("（应）重要数据存储机密性")
            app_check5.set_value(True)
            app_check6.set_text("（应）重要数据传输完整性")
            app_check6.set_value(True)
            app_check7.set_text("（应）重要数据存储完整性")
            app_check7.set_value(True)
            app_check8.set_text("（宜）不可否认性")

            # 更新管理制度
            manage_check4.set_text("（应）定期修订安全管理制度")
            manage_check4.set_value(True)
            manage_check5.set_text("（应）明确管理制度发布流程")
            manage_check5.set_value(True)
            manage_check6.set_text("（应）制度执行过程记录留存")
            manage_check6.set_value(True)

            # 更新人员管理
            personnel_check4.set_text("（应）定期进行安全岗位人员考核")
            personnel_check4.set_value(True)

            # 更新建设运行
            construct_check5.set_text("（应）定期密评与攻防演习")
            construct_check5.set_value(True)

            # 更新应急处置
            emergency_check2.set_text("（应）事件处置")
            emergency_check2.set_value(True)
            emergency_check3.set_text("（应）向有关主管部门上报处置情况")
            emergency_check3.set_value(True)

    # 计算分数函数
    def calculate_score():
        try:
            # 物理层计算
            physical_score = 0
            physical_weight = 0
            if physical_check1.value and physical_input1.value:
                physical_weight += 0.7 if level_radio.value == '二级系统' else 1
                physical_score += float(physical_input1.value) * (0.7 if level_radio.value == '二级系统' else 1)
            if physical_check2.value and physical_input2.value:
                physical_weight += 0.4 if level_radio.value == '二级系统' else 0.7
                physical_score += float(physical_input2.value) * (0.4 if level_radio.value == '二级系统' else 0.7)
            if physical_check3.value and physical_input3.value and level_radio.value == '三级系统':
                physical_weight += 0.7
                physical_score += float(physical_input3.value) * 0.7
            physical_result.set_text(f"物理层：{round(physical_score / physical_weight, 4) if physical_weight > 0 else '不适用'}")

            # 网络层计算
            network_score = 0
            network_weight = 0
            if network_check1.value and network_input1.value:
                network_weight += 0.7 if level_radio.value == '二级系统' else 1
                network_score += float(network_input1.value) * (0.7 if level_radio.value == '二级系统' else 1)
            if network_check2.value and network_input2.value:
                network_weight += 0.4 if level_radio.value == '二级系统' else 0.7
                network_score += float(network_input2.value) * (0.4 if level_radio.value == '二级系统' else 0.7)
            if network_check3.value and network_input3.value:
                network_weight += 0.7 if level_radio.value == '二级系统' else 1
                network_score += float(network_input3.value) * (0.7 if level_radio.value == '二级系统' else 1)
            if network_check4.value and network_input4.value:
                network_weight += 0.4 if level_radio.value == '二级系统' else 0.4
                network_score += float(network_input4.value) * (0.4 if level_radio.value == '二级系统' else 0.4)
            if network_check5.value and network_input5.value and level_radio.value == '三级系统':
                network_weight += 0.4
                network_score += float(network_input5.value) * 0.4
            network_result.set_text(f"网络层：{round(network_score / network_weight, 4) if network_weight > 0 else '不适用'}")

            # 设备层计算
            device_score = 0
            device_weight = 0
            if device_check1.value and device_input1.value:
                device_weight += 0.7 if level_radio.value == '二级系统' else 1
                device_score += float(device_input1.value) * (0.7 if level_radio.value == '二级系统' else 1)
            if device_check2.value and device_input2.value and level_radio.value == '三级系统':
                device_weight += 1
                device_score += float(device_input2.value) * 1
            if device_check3.value and device_input3.value:
                device_weight += 0.4 if level_radio.value == '二级系统' else 0.4
                device_score += float(device_input3.value) * (0.4 if level_radio.value == '二级系统' else 0.4)
            if device_check4.value and device_input4.value and level_radio.value == '三级系统':
                device_weight += 0.4
                device_score += float(device_input4.value) * 0.4
            if device_check5.value and device_input5.value:
                device_weight += 0.4 if level_radio.value == '二级系统' else 0.4
                device_score += float(device_input5.value) * (0.4 if level_radio.value == '二级系统' else 0.4)
            if device_check6.value and device_input6.value and level_radio.value == '三级系统':
                device_weight += 0.7
                device_score += float(device_input6.value) * 0.7
            device_result.set_text(f"设备层：{round(device_score / device_weight, 4) if device_weight > 0 else '不适用'}")

            # 应用层计算
            app_score = 0
            app_weight = 0
            if app_check1.value and app_input1.value:
                app_weight += 0.7 if level_radio.value == '二级系统' else 1
                app_score += float(app_input1.value) * (0.7 if level_radio.value == '二级系统' else 1)
            if app_check2.value and app_input2.value:
                app_weight += 0.4 if level_radio.value == '二级系统' else 0.4
                app_score += float(app_input2.value) * (0.4 if level_radio.value == '二级系统' else 0.4)
            if app_check3.value and app_input3.value and level_radio.value == '三级系统':
                app_weight += 0.4
                app_score += float(app_input3.value) * 0.4
            if app_check4.value and app_input4.value:
                app_weight += 0.7 if level_radio.value == '二级系统' else 1
                app_score += float(app_input4.value) * (0.7 if level_radio.value == '二级系统' else 1)
            if app_check5.value and app_input5.value:
                app_weight += 0.7 if level_radio.value == '二级系统' else 1
                app_score += float(app_input5.value) * (0.7 if level_radio.value == '二级系统' else 1)
            if app_check6.value and app_input6.value:
                app_weight += 0.7 if level_radio.value == '二级系统' else 0.7
                app_score += float(app_input6.value) * (0.7 if level_radio.value == '二级系统' else 0.7)
            if app_check7.value and app_input7.value:
                app_weight += 0.7 if level_radio.value == '二级系统' else 0.7
                app_score += float(app_input7.value) * (0.7 if level_radio.value == '二级系统' else 0.7)
            if app_check8.value and app_input8.value and level_radio.value == '三级系统':
                app_weight += 1
                app_score += float(app_input8.value) * 1
            app_result.set_text(f"应用层：{round(app_score / app_weight, 4) if app_weight > 0 else '不适用'}")

            # 管理制度计算
            manage_score = 0
            manage_weight = 0
            if manage_check1.value and manage_input1.value:
                manage_weight += 1
                manage_score += float(manage_input1.value) * 1
            if manage_check2.value and manage_input2.value:
                manage_weight += 0.7
                manage_score += float(manage_input2.value) * 0.7
            if manage_check3.value and manage_input3.value:
                manage_weight += 0.7
                manage_score += float(manage_input3.value) * 0.7
            if manage_check4.value and manage_input4.value and level_radio.value == '三级系统':
                manage_weight += 0.7
                manage_score += float(manage_input4.value) * 0.7
            if manage_check5.value and manage_input5.value and level_radio.value == '三级系统':
                manage_weight += 0.7
                manage_score += float(manage_input5.value) * 0.7
            if manage_check6.value and manage_input6.value and level_radio.value == '三级系统':
                manage_weight += 0.7
                manage_score += float(manage_input6.value) * 0.7
            manage_result.set_text(f"管理制度：{round(manage_score / manage_weight, 4) if manage_weight > 0 else '不适用'}")

            # 人员管理计算
            personnel_score = 0
            personnel_weight = 0
            if personnel_check1.value and personnel_input1.value:
                personnel_weight += 0.7
                personnel_score += float(personnel_input1.value) * 0.7
            if personnel_check2.value and personnel_input2.value:
                personnel_weight += 1
                personnel_score += float(personnel_input2.value) * 1
            if personnel_check3.value and personnel_input3.value:
                personnel_weight += 0.7
                personnel_score += float(personnel_input3.value) * 0.7
            if personnel_check4.value and personnel_input4.value and level_radio.value == '三级系统':
                personnel_weight += 0.7
                personnel_score += float(personnel_input4.value) * 0.7
            if personnel_check5.value and personnel_input5.value:
                personnel_weight += 0.7
                personnel_score += float(personnel_input5.value) * 0.7
            personnel_result.set_text(f"人员管理：{round(personnel_score / personnel_weight, 4) if personnel_weight > 0 else '不适用'}")

            # 建设运行计算
            construct_score = 0
            construct_weight = 0
            if construct_check1.value and construct_input1.value:
                construct_weight += 1
                construct_score += float(construct_input1.value) * 1
            if construct_check2.value and construct_input2.value:
                construct_weight += 1
                construct_score += float(construct_input2.value) * 1
            if construct_check3.value and construct_input3.value:
                construct_weight += 0.7
                construct_score += float(construct_input3.value) * 0.7
            if construct_check4.value and construct_input4.value:
                construct_weight += 1
                construct_score += float(construct_input4.value) * 1
            if construct_check5.value and construct_input5.value and level_radio.value == '三级系统':
                construct_weight += 0.7
                construct_score += float(construct_input5.value) * 0.7
            construct_result.set_text(f"建设运行：{round(construct_score / construct_weight, 4) if construct_weight > 0 else '不适用'}")

            # 应急处置计算
            emergency_score = 0
            emergency_weight = 0
            if emergency_check1.value and emergency_input1.value:
                emergency_weight += 1
                emergency_score += float(emergency_input1.value) * 1
            if emergency_check2.value and emergency_input2.value and level_radio.value == '三级系统':
                emergency_weight += 0.7
                emergency_score += float(emergency_input2.value) * 0.7
            if emergency_check3.value and emergency_input3.value and level_radio.value == '三级系统':
                emergency_weight += 0.7
                emergency_score += float(emergency_input3.value) * 0.7
            emergency_result.set_text(f"应急处置：{round(emergency_score / emergency_weight, 4) if emergency_weight > 0 else '不适用'}")

            # 总分计算
            total_technical = 0
            total_management = 0
            total_weight_tech = 0
            total_weight_mang = 0
            if physical_result.text != '物理层：不适用':
                total_technical += float(physical_result.text.split('：')[-1]) * 10
                total_weight_tech += 10
            if network_result.text != '网络层：不适用':
                total_technical += float(network_result.text.split('：')[-1]) * 20
                total_weight_tech += 20
            if device_result.text != '设备层：不适用':
                total_technical += float(device_result.text.split('：')[-1]) * 10
                total_weight_tech += 10
            if app_result.text != '应用层：不适用':
                total_technical += float(app_result.text.split('：')[-1]) * 30
                total_weight_tech += 30
            if manage_result.text != '管理制度：不适用':
                total_management += float(manage_result.text.split('：')[-1]) * 8
                total_weight_mang += 8
            if personnel_result.text != '人员管理：不适用':
                total_management += float(personnel_result.text.split('：')[-1]) * 8
                total_weight_mang += 8
            if construct_result.text != '建设运行：不适用':
                total_management += float(construct_result.text.split('：')[-1]) * 8
                total_weight_mang += 8
            if emergency_result.text != '应急处置：不适用':
                total_management += float(emergency_result.text.split('：')[-1]) * 6
                total_weight_mang += 6

            total_score = round((total_technical/total_weight_tech * 70 + total_management/total_weight_mang * 30) ,4)
            total_result.set_text(f"总分：{total_score}")

        except Exception as e:
            ui.notify(f"计算错误：{str(e)}")

    # 创建侧边栏
    sidebar_manager.create_sidebar(content)



# 挂载NiceGUI到FastAPI应用
ui.run_with(
    fastapi_app,
    mount_path='/',
    show_welcome_message=False
)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(fastapi_app, host="0.0.0.0", port=8000)