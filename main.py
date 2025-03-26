from fastapi import FastAPI
from nicegui import ui
import base64

from nicegui.tailwind_types import content

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
                ("/converter", "编码转换", "swap_horiz")
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
            ui.page_title("Draina的工具箱")

            with ui.column().classes("max-w-7xl mx-auto p-6 w-full h-full gap-4"):
                # 标题区
                ui.label("🔧 欢迎来到Draina的工具箱").classes("text-3xl font-bold text-center text-gray-800 mb-2")
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
                                    ''')

                    # 右侧侧边区
                    with ui.column().classes("w-80 space-y-6"):


                        # 开发者信息
                        with ui.card().classes("p-4 shadow-lg rounded-xl bg-purple-50"):
                            ui.label("💻 开发者信息").classes("text-xl font-bold text-purple-800 mb-3")
                            with ui.row().classes("items-center gap-4"):
                                ui.image("https://images.cnblogs.com/cnblogs_com/blogs/831993/galleries/2423491/o_240927082711_822965d76109d493feba06a0fe8f13d.jpg").classes("rounded-full")
                                with ui.column():
                                    ui.label("Draina").classes("font-bold")
                                    ui.markdown("密评工程师 | 编程爱好者").classes("text-sm text-gray-600")
                            ui.separator().classes("my-3")
                            with ui.column().classes("space-y-1 text-sm"):
                                ui.markdown('''
                                            📧 ​**邮箱**:    draina@qq.com  
                                            🖊  ​**Blogs**:  [Draina](https://www.cnblogs.com/Draina)  
                                            🐈 ​**GitHub**: [Draina233](https://github.com/Draina233)  
                                ''')
                # 页脚
                ui.separator().classes("mt-8")
                ui.label("© 2024 Draina's Toolbox | GPL-3.0 license").classes("text-center text-gray-500 text-sm py-2")

        # 创建侧边栏
        sidebar_manager.create_sidebar(content)


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

                # 输出区域
                with ui.card().classes("w-full p-4").style("min-height: 200px;"):
                    ui.label("转换结果：").classes("text-lg font-medium")
                    output_area = ui.label().classes("text-sm font-mono break-all").style("width: 100%")

                # 状态提示
                status = ui.label().classes("text-sm text-gray-500 px-2")

                # 转换处理函数（修改关键部分）
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
                # 页脚
                ui.separator().classes("mt-8")
                ui.label("© 2024 Draina's Toolbox | GPL-3.0 license").classes("text-center text-gray-500 text-sm py-2")

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