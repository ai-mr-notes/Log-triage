"""log_triage.py —— 把几万行日志压成一份可读的排查报告

用法：
    python log_triage.py app.log          # 默认只看 ERROR 及以上
    python log_triage.py app.log WARN     # 放宽到 WARN
"""

import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# 头部行：2026-10-14 09:31:02.145 ERROR com.demo.OrderService - 下单失败
HEAD = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+"
    r"(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s+"
    r"(?P<src>[^\s:]+)\s*[-:]\s?(?P<msg>.*)$"
)

# 堆栈续行：缩进的栈帧，或无缩进的异常首行
# （Java 的 java.lang.XxxException 通常顶格打印，不能漏）
CONT = re.compile(
    r'^\s+(?:at\s|File\s+"|\.\.\.|Caused by:|suppressed:)'
    r'|^\S*(?:Exception|Error|Throwable)\b')

LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "WARNING": 30,
          "ERROR": 40, "FATAL": 50, "CRITICAL": 50}


def parse_ts(text):
    """解析时间戳，失败返回 None，不阻断整份报告"""
    clean = re.sub(r"[.,]\d+$", "", text).replace("T", " ")
    try:
        return datetime.strptime(clean, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def parse(path, min_level="ERROR"):
    """把日志切成一条条记录，只保留级别 >= min_level 的"""
    threshold = LEVELS[min_level]
    records, current = [], None
    text = Path(path).read_text(encoding="utf-8", errors="ignore")

    for raw in text.splitlines():
        head = HEAD.match(raw)
        if head:
            if current is not None:
                records.append(current)
            current = {
                "ts": parse_ts(head["ts"]),
                "level": head["level"].upper(),
                "src": head["src"],
                "msg": head["msg"].strip(),
                "raw": raw,
                "stack": [],
            }
        elif current is not None and CONT.match(raw):
            # 堆栈行挂到上一条记录上，否则堆栈会全部丢掉
            current["stack"].append(raw.strip())

    if current is not None:
        records.append(current)
    return [r for r in records if LEVELS[r["level"]] >= threshold]


NOISE = [
    (re.compile(r"0x[0-9a-fA-F]+"), "0xN"),      # 内存地址
    (re.compile(r"\b\d{4,}\b"), "N"),            # 订单号 / ID / 毫秒
    (re.compile(r"\[[^\[\]]{1,40}\]"), "[]"),    # 线程名 / taskId
    (re.compile(r"[A-Za-z]:\\[^\s\"']+|/(?:[\w.\-]+/)+[\w.\-]+"), "PATH"),
    (re.compile(r":\d+(?=[:\s)]|$)"), ":N"),     # 行号
    (re.compile(r"\s+"), " "),
]


def signature(rec):
    """用一个稳定的字符串代表这类报错，作为合并的依据"""
    text = rec["msg"]
    for line in rec["stack"]:
        # 堆栈里的异常行比消息体更稳定，优先用它
        if re.search(r"(Exception|Error|Fail\w*)(:|\b)", line):
            text = line
            break
    for pattern, repl in NOISE:
        text = pattern.sub(repl, text)
    return text.strip()[:160] or "(无法识别的报错)"


FRAME = re.compile(
    r'File\s+"(?P<py>[^"]+)",\s+line\s+(?P<pyline>\d+)'            # Python
    r'|at\s+[\w.$]+\((?P<java>[^:()]+)(?::(?P<javaline>\d+))?\)'   # Java
    r'|(?P<js>[\w./\-]+\.(?:ts|js|vue)):(?P<jsline>\d+):\d+'       # 前端
)


def frame_of(rec):
    """从堆栈里抽出第一个可用的 文件:行号"""
    for line in rec["stack"]:
        m = FRAME.search(line)
        if not m:
            continue
        file = m["py"] or m["java"] or m["js"]
        line_no = m["pyline"] or m["javaline"] or m["jsline"]
        if file:
            return f"{file}:{line_no or '?'}"
    return None


def group(records):
    """按签名合并，出现次数多的排前面"""
    buckets = defaultdict(list)
    for rec in records:
        buckets[signature(rec)].append(rec)
    return sorted(buckets.values(), key=len, reverse=True)


def report(groups, top=10):
    total = sum(len(g) for g in groups)
    out = [f"# 日志排查报告：{total} 条告警，归并为 {len(groups)} 类", ""]
    for i, g in enumerate(groups[:top], 1):
        first = g[0]
        out.append(f"## {i}. {signature(first)}")
        out.append("")
        out.append(f"- 出现次数：{len(g)}")
        stamps = [r["ts"] for r in g if r["ts"]]
        if stamps:
            out.append(f"- 时间范围：{min(stamps):%Y-%m-%d %H:%M:%S} ~ "
                       f"{max(stamps):%Y-%m-%d %H:%M:%S}")
        out.append(f"- 来源：{', '.join(sorted({r['src'] for r in g}))}")
        code = next((frame_of(r) for r in g if frame_of(r)), None)
        if code:
            out.append(f"- 可疑代码位置：`{code}`")
        out.append("")
        out.append("```")
        out.append(first["raw"])
        out.extend(first["stack"][:3])
        out.append("```")
        out.append("")
    if len(groups) > top:
        rest = groups[top:]
        out.append(f"> 另有 {len(rest)} 类低频告警未展示，共 "
                   f"{sum(len(g) for g in rest)} 条。")
    return "\n".join(out)


if __name__ == "__main__":
    log_file = sys.argv[1] if len(sys.argv) > 1 else "app.log"
    min_level = (sys.argv[2] if len(sys.argv) > 2 else "ERROR").upper()
    print(report(group(parse(log_file, min_level))))
