# -*- coding: utf-8 -*-
"""图形界面（标准库实现，无需安装 gradio/streamlit）。

启动：
    python app.py
    浏览器打开 http://127.0.0.1:7860

功能：
    1. 从官方测试集选一条，实时看分析过程，出结论
    2. 手动粘贴函数，单条检测
    3. 批量跑前 N 条，产出官方格式 result.jsonl 并可下载
"""

from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import config
import dataio
import judge
import llm
import rag

SAMPLES: list[dict] = []      # 启动时加载（不解析父提交）
INDEX = None                  # 懒加载
STOP = threading.Event()      # 批量检测的停止信号，由 /api/stop 置位


# ---------------------------------------------------------------- 业务

def ensure_samples() -> list[dict]:
    global SAMPLES
    if not SAMPLES:
        SAMPLES = dataio.load_test(resolve_sha=False)
    return SAMPLES


def ensure_index():
    global INDEX
    if INDEX is None:
        INDEX = rag.get_index()
    return INDEX


def run_one(sample: dict, mode: str, emit) -> dict:
    if mode == "baseline":
        emit({"type": "status", "text": "基线模式：只把函数交给模型"})
        return judge.judge_baseline(sample)

    if mode == "rag":
        emit({"type": "status", "text": "检索历史相似案例…"})
        idx = ensure_index()
        cases = idx.search(sample["func"], k=config.TOP_K)
        emit({"type": "status",
              "text": f"检索到 {len(cases)} 条：" + ", ".join(d.get("cve", "?") for _, d in cases)})
        return judge.judge_rag(sample, cases)

    # full / agent：都走 agent 循环；full 额外注入检索到的案例
    cases = None
    if mode == "full":
        emit({"type": "status", "text": "检索历史相似案例…"})
        idx = ensure_index()
        cases = idx.search(sample["func"], k=config.TOP_K)
        emit({"type": "status",
              "text": f"检索到 {len(cases)} 条：" + ", ".join(d.get("cve", "?") for _, d in cases)})

    import repo

    def get_root():
        """惰性：模型第一次调用仓库工具时才解析 sha、下载、解压。

        早期版本在这里直接 repo.ensure()，结果每条样本都要下载仓库，
        单条 24 秒，300 条要 2 小时。改成回调后对大多数样本零下载。
        """
        if not sample.get("sha"):
            emit({"type": "status", "text": "解析该版本的提交 sha（需要 GitHub API）…"})
            parsed = dataio.parse_commit_url(sample.get("commit_url", ""))
            if not parsed:
                raise RuntimeError("commit_url 无法解析")
            owner, name, sha = parsed
            if sample.get("label") == 1:
                sha = dataio.parent_sha(owner, name, sha)
                emit({"type": "status", "text": f"漏洞版：父提交 {sha[:8]}"})
            sample["repo"] = f"{owner}/{name}"
            sample["sha"] = sha

        emit({"type": "status",
              "text": f"下载并解压 {sample['repo']}@{sample['sha'][:8]}（不含 .git）"})
        root = repo.ensure(sample)
        emit({"type": "status", "text": "仓库就绪，继续分析"})
        return root

    try:
        return judge.judge_agent(sample, get_root, on_event=emit, cases=cases)
    finally:
        repo.cleanup(sample)


# ---------------------------------------------------------------- 页面

PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"><title>函数漏洞检测智能体</title>
<style>
 :root{--bg:#13151a;--panel:#1c1f26;--line:#2a2f39;--fg:#e6e8ee;--dim:#98a1b0;
       --ok:#3ddc97;--bad:#ff6b6b;--acc:#4c7dff}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.65 "Segoe UI",system-ui,sans-serif}
 header{padding:14px 22px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:baseline}
 header h1{font-size:16px;margin:0}
 header span{color:var(--dim);font-size:12px}
 main{display:grid;grid-template-columns:minmax(420px,1fr) 1.1fr;gap:14px;padding:14px 22px 32px;max-width:1600px}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:13px}
 .card h2{font-size:12px;margin:0 0 9px;color:var(--dim);letter-spacing:.07em}
 label{display:block;font-size:12px;color:var(--dim);margin:7px 0 4px}
 select,input,textarea{width:100%;background:#0f1116;border:1px solid var(--line);border-radius:7px;
   color:var(--fg);padding:8px 9px;font-family:Consolas,monospace;font-size:12.5px}
 textarea{height:250px;resize:vertical}
 select,input{height:34px}
 .row{display:flex;gap:8px;margin-top:11px}
 button{flex:1;height:36px;border:0;border-radius:7px;background:var(--acc);color:#fff;cursor:pointer;font-size:13.5px}
 button:disabled{opacity:.45;cursor:not-allowed}
 button.ghost{background:#262b35;color:var(--fg);flex:0 0 auto;padding:0 12px}
 .trace{height:320px;overflow:auto;font-family:Consolas,monospace;font-size:12px}
 .step{border-left:2px solid var(--acc);padding:5px 0 5px 9px;margin-bottom:7px}
 .step .t{color:#7aa2ff}
 .step pre{margin:3px 0 0;white-space:pre-wrap;color:var(--dim);max-height:110px;overflow:auto}
 .verdict{display:none;margin-top:11px;padding:12px;border-radius:8px;background:#181b22;border:1px solid var(--line)}
 .verdict.show{display:block}
 .big{font-size:23px;font-weight:700}
 .vuln{color:var(--bad)} .safe{color:var(--ok)}
 .meta{color:var(--dim);font-size:12px}
 .muted{color:var(--dim)}
 .bar{height:5px;background:#22262f;border-radius:3px;overflow:hidden;margin-top:9px;display:none}
 .bar.show{display:block} .bar i{display:block;height:100%;width:0;background:var(--acc);transition:width .2s}
 a{color:var(--acc)}
</style>
</head>
<body>
<header><h1>函数漏洞检测智能体</h1>
<span>C/C++ 函数级漏洞检测 · 历史案例检索 + 仓库上下文</span></header>
<main>
  <section class="card">
    <h2>输入</h2>
    <label>模式</label>
    <select id="mode">
      <option value="full" selected>完整：RAG 检索 + 仓库工具（主方案）</option>
      <option value="rag">RAG：函数 + 历史相似案例</option>
      <option value="agent">Agent：函数 + 仓库工具</option>
      <option value="baseline">基线：只给函数</option>
    </select>

    <label>从官方测试集选择</label>
    <select id="pick"><option value="">— 手动输入 —</option></select>

    <label>函数代码（选样本后自动填入）</label>
    <textarea id="code" placeholder="粘贴 C/C++ 函数"></textarea>

    <div class="row">
      <button id="run">开始检测</button>
      <button class="ghost" id="load">载入样本</button>
    </div>

    <h2 style="margin-top:18px">批量检测</h2>
    <label>上传 .jsonl（官方格式：idx / commit_url / target / func）</label>
    <input id="file" type="file" accept=".jsonl,.json,.txt" style="height:auto;padding:6px">
    <div class="row">
      <input id="from" type="number" value="0" min="0" style="flex:0 0 80px" placeholder="起始">
      <input id="limit" type="number" value="20" min="1" style="flex:0 0 90px">
      <button id="batch">跑测试集 N 条</button>
      <button class="ghost" id="upload">上传并检测</button>
      <button class="ghost" id="stop" style="background:#7a2a2a">停止</button>
      <a id="dl" href="#" style="display:none;align-self:center;font-size:12px">下载结果</a>
    </div>
    <div class="bar" id="bar"><i></i></div>
  </section>

  <section class="card">
    <h2>分析过程</h2>
    <div class="trace" id="trace"><span class="muted">等待开始…</span></div>
    <div class="verdict" id="verdict">
      <div class="big" id="vres"></div>
      <div class="meta" id="vmeta"></div>
      <p id="vreason" style="margin:9px 0 0"></p>
    </div>
  </section>
</main>
<script>
const $ = id => document.getElementById(id);
const traceEl = $('trace');
let SAMPLES = [], CUR = null;

const esc = s => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

function addStep(html){
  const d = document.createElement('div');
  d.className = 'step'; d.innerHTML = html;
  traceEl.appendChild(d);
  traceEl.scrollTop = traceEl.scrollHeight;
}
function reset(){ traceEl.innerHTML=''; $('verdict').classList.remove('show'); }

async function boot(){
  const r = await fetch('/api/samples');
  SAMPLES = await r.json();
  const sel = $('pick');
  SAMPLES.forEach((s, i) => {
    const o = document.createElement('option');
    o.value = i;
    o.textContent = `#${s.idx}  target=${s.label}  ${s.repo}`;
    sel.appendChild(o);
  });
}

$('load').onclick = async () => {
  const i = $('pick').value;
  if(i === '') return alert('先选一条样本');
  const s = SAMPLES[Number(i)];
  const r = await fetch('/api/sample?idx=' + encodeURIComponent(s.idx));
  const d = await r.json();
  $('code').value = d.func;
  CUR = d;
};

async function stream(url, body, onEvent){
  const resp = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'},
                                 body: JSON.stringify(body)});
  const reader = resp.body.getReader(); const dec = new TextDecoder(); let buf='';
  while(true){
    const {done, value} = await reader.read();
    if(done) break;
    buf += dec.decode(value, {stream:true});
    let i;
    while((i = buf.indexOf('\n')) >= 0){
      const line = buf.slice(0,i); buf = buf.slice(i+1);
      if(line.trim()) onEvent(JSON.parse(line));
    }
  }
}

function onEvent(ev){
  if(ev.type === 'status') addStep(`<span class="t">${esc(ev.text)}</span>`);
  else if(ev.type === 'trace'){
    const tag = ev.duplicate ? '<span style="color:#ffb84d">[重复]</span> ' : '';
    addStep(`${tag}<span class="t">${esc(ev.tool)}</span> <span class="muted">第${ev.step}步</span>` +
            `<pre>${esc(JSON.stringify(ev.args))}\n${esc(ev.result).slice(0,600)}</pre>`);
  }
  else if(ev.type === 'final'){
    $('verdict').classList.add('show');
    const v = ev.prediction === 1;
    $('vres').textContent = v ? '有漏洞' : '无漏洞';
    $('vres').className = 'big ' + (v ? 'vuln' : 'safe');
    $('vmeta').textContent = (CUR ? `#${CUR.idx} · ` : '') +
      `工具 ${ev.steps||0} 次 · ${ev.tokens||0} tokens`;
    $('vreason').textContent = ev.reason || '';
  }
  else if(ev.type === 'progress'){
    $('bar').classList.add('show');
    $('bar').firstElementChild.style.width = (ev.done/ev.total*100) + '%';
    addStep(`<span class="muted">[${ev.done}/${ev.total}] #${esc(ev.idx)} → ${ev.prediction} ${esc(ev.note||'')}</span>`);
  }
  else if(ev.type === 'batch_done'){
    $('dl').style.display='inline';
    $('dl').href = '/download?name=' + encodeURIComponent(ev.file);
    addStep(`<span class="t">批量完成：${esc(ev.summary)}</span>`);
  }
  else if(ev.type === 'error') addStep(`<span style="color:#ff6b6b">错误</span><pre>${esc(ev.message)}</pre>`);
}

$('run').onclick = async () => {
  const code = $('code').value.trim();
  if(!code) return alert('先载入或粘贴一个函数');
  $('run').disabled = true; reset();
  const body = {mode: $('mode').value, code, idx: CUR ? CUR.idx : null,
                commit_url: CUR ? CUR.commit_url : null, label: CUR ? CUR.label : 0};
  try { await stream('/api/analyze', body, onEvent); }
  catch(e){ addStep(`<span style="color:#ff6b6b">${esc(e)}</span>`); }
  finally { $('run').disabled = false; }
};

$('stop').onclick = async () => {
  try {
    await fetch('/api/stop', {method:'POST', headers:{'Content-Type':'application/json'},
                              body: '{}'});
    addStep('<span style="color:#ffb84d">已发送停止指令，当前这条跑完就会停…</span>');
  } catch(e) { addStep(`<span style="color:#ff6b6b">${esc(e)}</span>`); }
};

$('batch').onclick = async () => {
  const n = Number($('limit').value) || 1;
  const from = Number($('from').value) || 0;
  $('batch').disabled = true; reset();
  $('bar').classList.add('show'); $('bar').firstElementChild.style.width='0';
  try { await stream('/api/batch', {mode: $('mode').value, limit: n, offset: from}, onEvent); }
  catch(e){ addStep(`<span style="color:#ff6b6b">${esc(e)}</span>`); }
  finally { $('batch').disabled = false; }
};

$('upload').onclick = async () => {
  const f = $('file').files[0];
  if(!f) return alert('先选一个 .jsonl 文件');
  const text = await f.text();
  $('upload').disabled = true; reset();
  $('bar').classList.add('show'); $('bar').firstElementChild.style.width='0';
  try {
    await stream('/api/upload', {mode: $('mode').value, content: text, name: f.name}, onEvent);
  } catch(e){ addStep(`<span style="color:#ff6b6b">${esc(e)}</span>`); }
  finally { $('upload').disabled = false; }
};

boot();
</script>
</body></html>
"""


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/samples":
            self._json(200, [{"idx": s["idx"], "label": s["label"], "repo": s["repo"]}
                             for s in ensure_samples()])
        elif path == "/api/sample":
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query)
            want = (q.get("idx") or [""])[0]
            for s in ensure_samples():
                if str(s["idx"]) == str(want):
                    self._json(200, s)
                    return
            self._json(404, {"error": "not found"})
        elif path == "/download":
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query)
            name = (q.get("name") or ["result_rag.jsonl"])[0]
            target = (config.OUT_DIR / name).resolve()
            if not str(target).startswith(str(config.OUT_DIR.resolve())) or not target.exists():
                self._json(404, {"error": "not found"})
                return
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self._json(404, {"error": "not found"})

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.end_headers()

        def emit(obj):
            self.wfile.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
            self.wfile.flush()
        return emit

    def do_POST(self):  # noqa: N802
        path = self.path.rstrip("/")

        # 停止接口：不流式返回，只置一个标记，正在跑的批次会在下一条样本前退出
        if path == "/api/stop":
            STOP.set()
            self._json(200, {"stopped": True})
            return

        if path not in ("/api/analyze", "/api/batch", "/api/upload"):
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "bad json"})
            return

        emit = self._stream()
        try:
            if path == "/api/analyze":
                self._analyze(payload, emit)
            elif path == "/api/upload":
                self._upload(payload, emit)
            else:
                self._batch(payload, emit)
        except BaseException as exc:  # noqa: BLE001
            # 注意：这里必须捕获 BaseException —— llm.chat 在缺少 key 时抛的是
            # SystemExit，它不属于 Exception，漏掉就会让连接直接断开、页面毫无反应。
            emit({"type": "error", "message": f"{type(exc).__name__}: {exc}"})

    def _analyze(self, payload, emit):
        mode = payload.get("mode", "rag")
        code = (payload.get("code") or "").strip()
        if not code:
            emit({"type": "error", "message": "没有函数代码"})
            return
        sample = {
            "idx": payload.get("idx") or "ui",
            "label": int(payload.get("label") or 0),
            "func": code,
            "commit_url": payload.get("commit_url") or "",
            "repo": None, "sha": None,
        }
        out = run_one(sample, mode, emit)
        emit({"type": "final", "prediction": out["prediction"], "reason": out["reason"],
              "steps": out.get("steps", 0), "tokens": out.get("usage", 0)})

    def _batch(self, payload, emit):
        mode = payload.get("mode", "rag")
        limit = int(payload.get("limit", 20))
        offset = int(payload.get("offset", 0))
        samples = ensure_samples()[offset: offset + limit]
        self._run_batch(samples, mode, emit, f"result_{mode}.jsonl")

    def _upload(self, payload, emit):
        """上传 .jsonl 批量检测（PPT 要求的批量上传入口）。"""
        mode = payload.get("mode", "full")
        content = payload.get("content") or ""
        rows, bad = [], 0
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if not isinstance(r, dict) or "func" not in r:
                bad += 1
                continue
            rows.append({
                "idx": r.get("idx"),
                "label": int(r.get("target") or 0),
                "func": r.get("func") or "",
                "commit_url": r.get("commit_url") or "",
                "repo": None, "sha": None,
            })
        if not rows:
            emit({"type": "error", "message": "文件里没有可用的记录（需要 func 字段）"})
            return
        emit({"type": "status",
              "text": f"解析 {len(rows)} 条记录" + (f"，跳过 {bad} 条格式错误" if bad else "")})
        self._run_batch(rows, mode, emit, "result_upload.jsonl")

    def _run_batch(self, samples, mode, emit, out_name):
        out_path = config.OUT_DIR / out_name
        # result_full.jsonl → traces_full.jsonl（和命令行版保持同一个命名）
        trace_name = out_name[7:] if out_name.startswith("result_") else out_name
        trace_path = config.OUT_DIR / ("traces_" + trace_name)
        ok = failed = 0
        tokens = 0
        t0 = time.time()
        STOP.clear()          # 新批次开始，清掉上一次的停止标记

        with out_path.open("w", encoding="utf-8") as fr, trace_path.open("w", encoding="utf-8") as ft:
            for i, s in enumerate(samples, 1):
                if STOP.is_set():
                    emit({"type": "error",
                          "message": f"已停止：完成 {i - 1} / {len(samples)} 条（已跑的部分已写入文件）"})
                    break
                err = None
                started = time.time()
                try:
                    out = run_one(s, mode, lambda ev: None)
                    ok += 1
                except BaseException as exc:  # noqa: BLE001
                    out = {"prediction": 0, "reason": "", "usage": 0, "steps": 0, "trace": [], "cases": []}
                    err = f"{type(exc).__name__}: {exc}"
                    failed += 1
                    emit({"type": "error", "message": f"{s['idx']}: {err}"})
                    if failed >= 3 and ok == 0:
                        emit({"type": "error",
                              "message": "连续失败 3 条，已中止。请检查 DEEPSEEK_API_KEY 是否正确。"})
                        break
                tokens += out.get("usage", 0)
                fr.write(json.dumps({"idx": s["idx"], "prediction": out["prediction"]},
                                    ensure_ascii=False) + "\n")
                fr.flush()
                ft.write(json.dumps({
                    "idx": s["idx"], "label": s.get("label"),
                    "commit_url": s.get("commit_url"), "repo": s.get("repo"), "sha": s.get("sha"),
                    "prediction": out["prediction"], "reason": out.get("reason", ""),
                    "cases": out.get("cases", []), "steps": out.get("steps", 0),
                    "usage": out.get("usage", 0), "trace": out.get("trace", []),
                    "error": err, "elapsed": round(time.time() - started, 1),
                }, ensure_ascii=False) + "\n")
                ft.flush()
                emit({"type": "progress", "done": i, "total": len(samples), "idx": s["idx"],
                      "prediction": out["prediction"],
                      "note": (err or out.get("reason", ""))[:60]})

        emit({"type": "batch_done", "file": out_name,
              "summary": f"成功 {ok} 失败 {failed}，{tokens} tokens，"
                         f"{(time.time()-t0)/60:.1f} 分钟"})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7860)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)

    if args.selftest:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        with urllib.request.urlopen(f"http://127.0.0.1:{args.port}/", timeout=5) as r:
            page = r.read()
        with urllib.request.urlopen(f"http://127.0.0.1:{args.port}/api/samples", timeout=10) as r:
            n = len(json.loads(r.read()))
        print(f"selftest: 页面 {len(page)} 字节，样本 {n} 条")
        server.shutdown()
        return 0

    url = f"http://127.0.0.1:{args.port}"
    print(f"界面已启动：{url}    （Ctrl+C 退出）")
    if not config.API_KEY:
        print("[警告] 没有检测到 DEEPSEEK_API_KEY —— 检测会立刻失败。")
        print("       先在终端执行：$env:DEEPSEEK_API_KEY = \"sk-...\"  然后重启本程序。")
    else:
        print(f"API key: 已读取（长度 {len(config.API_KEY)}）")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
