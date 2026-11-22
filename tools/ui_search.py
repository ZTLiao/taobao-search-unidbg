#!/usr/bin/env python3
"""UI 自动化驱动真机淘宝 App 搜索（免 root / 免 hook / 游客态）。

原理：用 adb 模拟真人操作真机 App 的搜索 UI，uiautomator dump 提取结果页文本。
请求由真机 App 自己的 anetwork 原生栈发出（自动签名 + 原生请求形态），
因此绕过手工 HTTP form 被 bixi 标 wh_ttid=pc 的 web 风控。

用法：
  python3 tools/ui_search.py --q iphone17              # 文本搜索
  python3 tools/ui_search.py --q iphone17 --fresh       # 先全新安装淘宝（清风控状态）
  python3 tools/ui_search.py --image /tmp/tb_img/x.jpg  # 图片搜索（拍立淘）

输出：JSON {success, items:[{title,price,...}], uiText:[...], activity, ...}
"""
import argparse, json, os, re, subprocess, sys, time

ADB = "/Users/liaozetao/.local/android/sdk/platform-tools/adb"
PKG = "com.taobao.taobao"
MAIN = PKG + "/com.taobao.tao.TBMainActivity"
APK = "/Users/liaozetao/Projects/ReaProjects/app/com.taobao.taobao.apk"
SERIAL = os.environ.get("TB_SERIAL", "d14172b5")


def adb(*args, timeout=20):
    try:
        return subprocess.run([ADB, "-s", SERIAL] + list(args),
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout).stdout.decode("utf-8", "ignore")
    except subprocess.TimeoutExpired:
        return ""


def ui_text():
    adb("shell", "uiautomator", "dump", "/sdcard/_ui.xml", timeout=25)
    xml = adb("shell", "cat", "/sdcard/_ui.xml", timeout=15)
    texts = re.findall(r'text="([^"]*)"', xml)
    return [t for t in texts if t.strip()], xml


def activity():
    out = adb("shell", "dumpsys", "activity", "activities", timeout=15)
    m = re.search(r'topResumedActivity=ActivityRecord\{[^}]* (\S+?) ', out)
    return m.group(1) if m else ""


def wait_activity(keyword, tries=15, gap=1):
    for _ in range(tries):
        a = activity()
        if keyword.lower() in a.lower():
            return a
        time.sleep(gap)
    return activity()


def tap(x, y):
    adb("shell", "input", "tap", str(x), str(y))
    time.sleep(0.5)


def find_bounds(xml, text=None, desc=None):
    """找 text= 或 content-desc= 匹配节点的中心坐标。"""
    for m in re.finditer(r'<node[^>]*/>', xml):
        node = m.group(0)
        hit = (text and ('text="%s"' % text) in node) or \
              (desc and ('content-desc="%s"' % desc) in node)
        if not hit:
            continue
        b = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', node)
        if b:
            x1, y1, x2, y2 = map(int, b.groups())
            if x2 > x1 and y2 > y1:
                return (x1 + x2) // 2, (y1 + y2) // 2
    return None


def parse_items(xml):
    """从结果页 UI XML 提取商品标题 + 价格。"""
    items = []
    nodes = re.findall(r'<node[^>]*/>', xml)
    titles, prices = [], []
    for node in nodes:
        t = re.search(r'text="([^"]*)"', node)
        if not t:
            continue
        val = t.group(1).strip()
        if not val:
            continue
        rid = re.search(r'resource-id="([^"]*)"', node)
        rid = rid.group(1) if rid else ""
        # 价格：¥ 开头或纯数字（两位小数），过滤掉明显非商品价格
        if val.startswith("¥") or re.match(r'^\d+\.\d{2}$', val):
            prices.append(val)
        elif len(val) >= 6 and not val.startswith("http"):
            titles.append(val)
    for i in range(max(len(titles), len(prices))):
        items.append({
            "title": titles[i] if i < len(titles) else "",
            "price": prices[i] if i < len(prices) else "",
        })
    return items


def fresh_install():
    print("[*] 全新安装淘宝（清风控状态）", flush=True)
    adb("uninstall", PKG, timeout=60)
    adb("install", APK, timeout=120)


def do_text_search(q):
    result = {"success": False, "query": q, "mode": "ui-automation",
              "session": "guest-no-login", "requestStack": "app-native-anetwork-ui"}
    print("[*] 复位：强制停止淘宝", flush=True)
    adb("shell", "am", "force-stop", PKG)
    time.sleep(2)
    print("[*] 启动淘宝首页", flush=True)
    adb("shell", "monkey", "-p", PKG, "-c",
        "android.intent.category.LAUNCHER", "1")
    a = wait_activity("TBMainActivity", tries=12, gap=1)
    # Welcome 页：等待自然过渡，若有"同意/进入"按钮则点击
    for _ in range(10):
        a = activity()
        if "TBMainActivity" in a:
            break
        if "Welcome" in a:
            texts, xml = ui_text()
            agree = (find_bounds(xml, text="同意") or find_bounds(xml, text="同意并继续")
                     or find_bounds(xml, text="进入"))
            if agree:
                tap(*agree)
            else:
                time.sleep(2)
        else:
            time.sleep(1.5)
    a = wait_activity("TBMainActivity", tries=15)
    time.sleep(4)
    texts, xml = ui_text()
    print("[*] 首页 activity=%s 文本数=%d" % (a, len(texts)), flush=True)

    # 找搜索栏
    pos = find_bounds(xml, desc="搜索栏") or find_bounds(xml, desc="搜索")
    print("[*] 搜索栏坐标=%s" % (pos,), flush=True)
    if not pos:
        result["error"] = "首页未找到搜索栏"
        result["uiText"] = texts[:30]
        return result

    tap(*pos)
    time.sleep(2)
    # 搜索输入页
    texts, xml = ui_text()
    inp = find_bounds(xml, desc="搜索") or find_bounds(xml, text="搜索")
    # 找 EditText
    for m in re.finditer(r'<node[^>]*android.widget.EditText[^>]*/>', xml):
        b = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', m.group(0))
        if b:
            x1, y1, x2, y2 = map(int, b.groups())
            inp = ((x1 + x2) // 2, (y1 + y2) // 2)
            break
    print("[*] 输入框坐标=%s" % (inp,), flush=True)
    if inp:
        tap(*inp)
    adb("shell", "input", "text", q)
    time.sleep(1)
    adb("shell", "input", "keyevent", "66")  # ENTER
    print("[*] 已提交搜索，等待结果页渲染", flush=True)
    time.sleep(8)

    a = activity()
    texts, xml = ui_text()
    items = parse_items(xml)
    result["activity"] = a
    result["uiText"] = texts[:60]
    result["items"] = items
    joined = " ".join(texts)
    if "登录后畅快搜索" in joined or "UserLoginActivity" in a:
        result["error"] = "被引导登录墙（bixi 要求登录）"
        result["gatewayRet"] = "RISK_CONTROL"
    elif len(items) > 0:
        result["success"] = True
        result["gatewayRet"] = "SUCCESS"
    else:
        result["error"] = "结果页无商品数据（可能加载中或被风控）"
    return result


def do_image_search(img_path):
    result = {"success": False, "image": img_path, "mode": "ui-automation",
              "session": "guest-no-login", "requestStack": "app-native-anetwork-ui"}
    if not os.path.exists(img_path):
        result["error"] = "图片不存在: " + img_path
        return result
    remote = "/sdcard/Pictures/tb_search.jpg"
    adb("push", img_path, remote, timeout=30)
    print("[*] 启动淘宝首页", flush=True)
    adb("shell", "monkey", "-p", PKG, "-c",
        "android.intent.category.LAUNCHER", "1")
    wait_activity("TBMainActivity", tries=25)
    time.sleep(4)
    texts, xml = ui_text()
    # 找拍照/相机图标（拍立淘入口），通常是搜索框右侧的相机图标
    cam = None
    for m in re.finditer(r'<node[^>]*/>', xml):
        node = m.group(0)
        desc = re.search(r'content-desc="([^"]*)"', node)
        d = desc.group(1) if desc else ""
        if any(k in d for k in ["拍照", "相机", "拍立淘", "搜图", "图片"]):
            b = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', node)
            if b:
                x1, y1, x2, y2 = map(int, b.groups())
                cam = ((x1 + x2) // 2, (y1 + y2) // 2)
                break
    print("[*] 拍立淘入口坐标=%s" % (cam,), flush=True)
    result["cameraPos"] = cam
    result["uiText"] = texts[:40]
    if not cam:
        result["error"] = "首页未找到拍立淘/拍照入口（需从搜索页进入）"
        return result
    result["hint"] = "拍立淘入口已定位，图搜需进一步模拟选图流程"
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--q", help="文本搜索关键词")
    ap.add_argument("--image", help="图片搜索的本地图片路径")
    ap.add_argument("--fresh", action="store_true", help="先全新安装淘宝")
    args = ap.parse_args()
    if args.fresh:
        fresh_install()
    if args.q:
        r = do_text_search(args.q)
    elif args.image:
        r = do_image_search(args.image)
    else:
        r = {"error": "需指定 --q 或 --image"}
    print("===RESULT_JSON===")
    print(json.dumps(r, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
