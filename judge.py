# -*- coding: utf-8 -*-
"""判定核心：四种模式。

    baseline  只给函数                        （最便宜，标尺）
    rag       函数 + 检索到的历史案例          （无工具，消融对比）
    agent     函数 + 仓库工具                  （无案例，消融对比）
    full      函数 + 案例 + 仓库工具           （主方案）

四种模式共用同一套判定口径，只有输入不同，保证对比公平。
"""

from __future__ import annotations

import json

import config
import llm
import tools

# ---------------------------------------------------------------- 判定口径

SYSTEM = """你是一名资深 C/C++ 安全审计员。你要判断：这个函数里的危险内存操作，是否都被函数内的校验保护住了。

按三步做，不要跳步：

第 1 步：列出危险操作。
   只列真正涉及内存的：数组读写、memcpy/strcpy 类拷贝、指针解引用、循环边界、
   用变量算出的分配大小、结构体字段偏移。
   纯算术、日志、赋值不要列。**最多 3 条，按危险程度降序**，第一条必须是最可能出问题的那条。

第 2 步：为每个危险操作找"守护校验"。
   在函数里找约束该操作所用变量的 if / 宏 / assert / 早退。
   要求：这个校验必须在通往该操作的路径上，而且约束的正是该操作实际使用的量。
   找不到就写 "NONE"。

第 3 步：给结论。
   **只看第一条（最危险的那条）**：它没有守护校验 → prediction 判 1；它有校验 → 判 0。
   不要因为第二、第三条没被保护就判 1。

注意：
- 不要因为"需要极大输入才能触发"就放过；缺少校验本身就是缺陷。
- 也不要因为出现 memcpy/strcpy 就判 1；它前面若已限制长度，就算被保护。
- 校验必须约束"实际使用"的量。例如循环用到的是 n，只校验了 m，就不算保护。

输出 JSON，不要输出其它文字：
{"ops":[{"op":"危险操作","guard":"具体校验语句或 NONE","protected":true}],
 "prediction":0或1,"confidence":0.0-1.0,"reason":"一句话总结"}
"""

RAG_ADD = """

下面会给你若干条「历史相似漏洞案例」。使用规则：
- 案例只是参考，不是答案。不要因为案例里有洞，就判断当前函数有洞。
- 先找当前函数与案例的**相同缺陷模式**，再检查当前函数是否已经补上了防护。
- 如果当前函数的写法与案例有实质差异，以当前代码为准。
- 在 reason 中可以说明"与案例 X 属于同一类（CWE-…）"，但结论必须基于当前代码。
"""

AGENT_ADD = """

你可以调用工具查看仓库上下文（search_code / read_file / list_dir）。

满足以下任一条件时，**必须先查证再下结论**：
1. 函数里出现了本文件未定义的宏或常量（如 MAX_LEN、BUF_SIZE、ARRAY_SIZE）——
   它的值直接决定边界条件是否成立。
2. 函数调用了本文件未定义的辅助函数，且该函数的返回值或行为影响内存访问。
3. 函数参数是缓冲区指针，而函数内部没有校验它的大小。

其余情况不必调用：函数内部已能完整判定时直接给结论，不要为了查而查。

同一工具、同一参数不要重复调用；最多 3 轮。
"""


def _messages(sample: dict, *, cases=None, with_tools: bool = False) -> list[dict]:
    system = SYSTEM
    if cases is not None:
        system += RAG_ADD
    if with_tools:
        system += AGENT_ADD

    parts: list[str] = []
    if cases:
        parts.append(f"历史相似漏洞案例（{len(cases)} 条，仅供参考）：\n")
        for i, (score, doc) in enumerate(cases, 1):
            desc = (doc.get("cve_desc") or "")[:200]
            parts.append(
                f"[案例{i}] {doc.get('cve') or '未知'}  {doc.get('cwe') or ''}  相似度 {score:.1f}\n"
                + (f"描述：{desc}\n" if desc else "")
                + f"```c\n{doc.get('func', '')[: config.CASE_CHARS]}\n```\n"
            )
    elif cases is not None:
        parts.append("（历史案例库中没有检索到相似案例，请仅基于代码本身判断。）\n")

    parts.append(f"待判断的函数：\n```c\n{sample['func']}\n```\n\n这个函数是否存在可被利用的安全漏洞？")
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": "\n".join(parts)},
    ]


def _verdict(data: dict, usage: int = 0, steps: int = 0,
             trace: list | None = None, cases: list | None = None) -> dict:
    pred = int(data.get("prediction", 0) or 0)
    pred = pred if pred in (0, 1) else 0

    # 标签由 ops 清单机械决定：只要有一条危险操作没被保护，就是有洞。
    # 这样比让模型"整体感觉"更稳定，也更容易解释。
    ops = data.get("ops")
    if isinstance(ops, list) and ops:
        first = ops[0] if isinstance(ops[0], dict) else {}
        pred = 0 if first.get("protected") else 1

    return {
        "prediction": pred,
        "confidence": float(data.get("confidence") or 0.0),
        "reason": str(data.get("reason") or "") or "模型未给出可解析的结论",
        "evidence": [o.get("op", "") for o in (ops or []) if isinstance(o, dict)],
        "ops": ops or [],
        "usage": usage,
        "steps": steps,
        "trace": trace or [],
        "cases": [d.get("cve") for _, d in (cases or [])],
    }


# ---------------------------------------------------------------- 三种模式

def judge_baseline(sample: dict) -> dict:
    resp = llm.chat(_messages(sample), json_mode=True)
    return _verdict(llm.parse_verdict(resp["choices"][0]["message"].get("content") or ""),
                    usage=llm.tokens_of(resp))


def judge_rag(sample: dict, cases: list[tuple[float, dict]]) -> dict:
    resp = llm.chat(_messages(sample, cases=cases), json_mode=True)
    return _verdict(llm.parse_verdict(resp["choices"][0]["message"].get("content") or ""),
                    usage=llm.tokens_of(resp), cases=cases)


def judge_agent(sample: dict, get_root, on_event=None, cases=None) -> dict:
    """带工具的自主判定。

    cases 不为 None 时，先把检索到的历史案例注入上下文（RAG 模块），
    模型仍然可以自主决定要不要再去仓库取证。这就是 PPT 第 4 页的 pipeline：
        检索知识库 → 初步分析 → 按需读仓库 → 报告

    get_root 是惰性的：模型第一次调用仓库工具时才真正下载解压。
    """
    messages = _messages(sample, cases=cases, with_tools=True)
    usage = 0
    trace: list[dict] = []
    seen: set[tuple[str, str]] = set()
    root = None

    def emit(ev: dict) -> None:
        if on_event:
            try:
                on_event(ev)
            except Exception:      # noqa: BLE001
                pass

    for step in range(config.MAX_STEPS):
        resp = llm.chat(messages, tools=tools.TOOLS)
        usage += llm.tokens_of(resp)
        msg = resp["choices"][0]["message"]
        calls = msg.get("tool_calls") or []

        if not calls:
            out = _verdict(llm.parse_verdict(msg.get("content") or ""), usage=usage,
                           steps=step, trace=trace, cases=cases)
            out["used_tools"] = bool(trace)
            emit({"type": "final", "prediction": out["prediction"], "reason": out["reason"],
                  "steps": step})
            return out

        messages.append({"role": "assistant", "content": msg.get("content") or "",
                         "tool_calls": calls})
        for call in calls:
            fn = call.get("function", {})
            name = fn.get("name", "")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}

            key = (name, json.dumps(args, sort_keys=True, ensure_ascii=False))
            dup = key in seen
            if dup:
                result = "【重复调用】结果同上一条，请换目标或直接给结论。"
            else:
                seen.add(key)
                # 惰性：第一次真的需要仓库时才解析 sha、下载、解压
                if name in ("search_code", "read_file", "list_dir") and root is None:
                    try:
                        root = get_root()
                    except Exception as exc:       # noqa: BLE001
                        result = f"仓库不可用（{exc}）。请仅基于函数代码与历史案例判断。"
                        emit({"type": "status", "text": f"仓库不可用：{exc}"})
                        trace.append({"step": step + 1, "tool": name, "args": args,
                                      "duplicate": False, "result": result})
                        messages.append({"role": "tool",
                                         "tool_call_id": call.get("id", ""),
                                         "content": result})
                        continue
                result = tools.dispatch(root, name, args)
                left = config.MAX_STEPS - step - 1
                result += f"\n\n（本次调用后还剩 {left} 次工具机会）"
            trace.append({"step": step + 1, "tool": name, "args": args,
                          "duplicate": dup, "result": result[:800]})
            emit({"type": "trace", "step": step + 1, "tool": name, "args": args,
                  "duplicate": dup, "result": result[:1200]})
            messages.append({"role": "tool", "tool_call_id": call.get("id", ""),
                             "content": result})

    messages.append({"role": "user", "content": "工具次数已用完，基于现有证据给出最终结论，只输出 JSON。"})
    resp = llm.chat(messages, json_mode=True)
    usage += llm.tokens_of(resp)
    out = _verdict(llm.parse_verdict(resp["choices"][0]["message"].get("content") or ""),
                   usage=usage, steps=config.MAX_STEPS, trace=trace, cases=cases)
    out["reason"] += "（步数耗尽）"
    emit({"type": "final", "prediction": out["prediction"], "reason": out["reason"],
          "steps": config.MAX_STEPS})
    return out
