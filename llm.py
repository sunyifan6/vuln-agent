# -*- coding: utf-8 -*-
"""LLM 客户端：一次调用 + 结论解析。

结论解析分四层降级，任何情况下都不抛异常：
    1) 直接 json.loads
    2) 去掉 ``` 围栏再试
    3) 正则抓文本里每个 {...}，取最后一个带 prediction 的
    4) 从文本里抠 "prediction: 1" 这样的数字
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

import config


class LLMError(RuntimeError):
    pass


def chat(messages: list[dict], *, tools: list[dict] | None = None,
         json_mode: bool = False, retries: int = 3) -> dict:
    if not config.API_KEY:
        raise SystemExit(
            "没有配置 API key。请打开 config.py，把顶部的 API_KEY 填成 \"sk-...\"。"
        )

    headers = {"Content-Type": "application/json",
               "Authorization": f"Bearer {config.API_KEY}"}
    url = config.BASE_URL + "/chat/completions"

    budget = config.MAX_TOKENS
    last: Exception | None = None

    for attempt in range(retries + 2):
        body: dict = {
            "model": config.MODEL,
            "messages": messages,
            "temperature": 0,
            "max_tokens": budget,
        }
        if tools:
            body["tools"] = tools
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        if not config.THINKING:
            body["thinking"] = {"type": "disabled"}

        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=config.TIMEOUT) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:300].decode("utf-8", "replace")
            if exc.code == 401:
                raise SystemExit("401：key 无效") from None
            if exc.code in (429, 500, 502, 503, 504):
                last = LLMError(f"HTTP {exc.code}")
                time.sleep(2 ** min(attempt, 4))
                continue
            raise LLMError(f"HTTP {exc.code}: {detail}") from None
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            last = LLMError(str(exc))
            time.sleep(2 ** min(attempt, 4))
            continue

        # 思考模式会吃掉 max_tokens：如果被截断且没有正文，加倍重试一次
        choice = (data.get("choices") or [{}])[0]
        content = (choice.get("message") or {}).get("content") or ""
        if choice.get("finish_reason") == "length" and not content.strip() and budget < 32000:
            budget = min(budget * 2, 32000)
            continue
        return data

    raise last or LLMError("调用失败")


def parse_verdict(text: str) -> dict:
    text = (text or "").strip()
    if not text:
        return {}

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", text)
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    found: dict = {}
    for m in re.finditer(r"\{[^{}]*\}", text, re.S):
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "prediction" in obj:
            found = obj
    if found:
        return found

    m = re.search(r"prediction[\"'\s]*[:：]?\s*[\"']?([01])\b", text)
    if m:
        return {"prediction": int(m.group(1)),
                "reason": "（结论 JSON 不合法，已从文本中提取 prediction）"}
    return {}


def tokens_of(resp: dict) -> int:
    return (resp.get("usage") or {}).get("total_tokens", 0) or 0
