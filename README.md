# 函数漏洞检测智能体

C/C++ 函数级漏洞检测：判断一个函数是否存在安全缺陷。
提交文件：`out/result_final.jsonl`（官方格式 `{"idx": 整数, "prediction": 0|1}`）。

**零第三方依赖** —— 只用 Python 3.10+ 标准库，不需要 `pip install` 任何东西。

## 使用前必做：填 API key

打开 `config.py`，第 11 行附近有一处：

```python
API_KEY = ""     
```

key 到 https://platform.deepseek.com/api_keys 申请。

> ⚠️ **上传 GitHub 之前，务必把这一行清空成 `API_KEY = ""`**，
> 否则密钥会随代码公开。`config.py` 是要提交的文件。
> 上传前可以自查一次：`git diff --cached | Select-String "sk-"`（应无输出）。

## 快速开始

```powershell
# 1. 在 config.py 顶部填好 API_KEY

# 2. 先跑 4 条验证链路（约 1 元、30 秒）
python run_all.py --mode full --limit 4

# 3. 全量 300 条 + 评测（约 30 分钟、12 元）
python run_final.py

# 4. 图形界面
python app.py            # → http://127.0.0.1:7860
```

## 在新机器上复现

仓库**不含密钥**，也**不含数据集**（数据由课程提供）。拿到项目后需要准备两样东西：

| 需要 | 怎么准备 |
|---|---|
| **API key** | 申请后填进 `config.py` 顶部的 `API_KEY` |
| **数据集** | 把 `test.jsonl` / `knowledge.jsonl` / `evaluation.py` 放到 `../dataset/dataset/`，或用 `$env:VULN_DATASET_DIR` 指向别处 |

**首次运行会自动做两件事**：建 `cache/bm25.json` 检索索引（约 1 分钟、10.5 MB）、
按需下载仓库快照（只有模型决定查仓库时才下载，缓存在 `cache/tars/`）。

依赖只有 Python 3.10+，不需要 `pip install`；`python-pptx` 只在重新生成 `docs/` 里的 PPT 时才需要。

忘了填 key 时，程序会直接报错：

```
没有配置 API key。请打开 config.py，把顶部的 API_KEY 填成 "sk-..."。
```


## 实测成绩（官方 `evaluation.py`，150 对全部评测）

| 模式 | 说明 | P-C | P-V | P-B | P-R | 等级 |
|---|---|---|---|---|---|---|
| baseline | 只给函数 | 30 | 65 | 38 | 17 | B（P-R>15 降级） |
| rag | 函数 + 检索案例，无工具 | 28 | 69 | 44 | 9 | B |
| agent | 函数 + 仓库工具，无 RAG | 33 | 69 | 39 | 9 | A |
| **full（主方案）** | **RAG 检索 + 仓库工具** | **32** | 71 | 36 | **11** | **A** |

等级规则：P-C ≥ 30 → A，25–29 → B；P-R > P-C/2 时降一级。
full 的 P-C=32、P-R=11 ≤ 16，不降级。

### 必须同时说清楚的局限

- **单次运行有波动**：同一 full 配置跑过三次，P-C 分别是 31 / 29 / 32，等级在 A/B 边界摆动。
  保守表述应为 **P-C 29～32**。
- **与随机基线无显著差异**：模型阳性率 61.7%，若按同阳性率独立随机猜测，P-C 期望 ≈ 35.5，
  实测 32 低于该值，差 3.5 对 < σ≈5。
- **但模型确实有判别力**：在给出不同标签的 43 对里，判对 32、判反 11，二项检验 p=0.002。
  问题不是"分不清"，而是"不敢分"——71.3% 的配对给出了相同标签。

## 系统流程（对应 PPT 第 4 页）

```
输入：函数代码 + 修复提交链接
        │
   ① 检索知识库（BM25，top-3 同类 CVE 案例）
        │
   ② Agent 自主分析 —— 模型自己决定要不要去仓库取证
        │   ├─ search_code   搜调用方 / 宏 / 类型定义
        │   ├─ read_file     读具体实现
        │   └─ list_dir      看目录结构
        │   （仓库懒加载：不调工具就不下载）
        │
   ③ 输出：prediction + 判定理由 + 分析记录
```

## 目录

| 文件 | 作用 |
|---|---|
| `config.py` | 路径、模型、超参、密钥读取 |
| `dataio.py` | 读官方 test/knowledge，解析提交链接与父提交（磁盘缓存） |
| `rag.py` | BM25 检索（3789 条历史漏洞案例，零依赖） |
| `llm.py` | API 客户端；**默认关闭思考模式**；结论解析四层降级 |
| `tools.py` | 三个只读仓库工具（search_code / read_file / list_dir） |
| `repo.py` | 按 sha 下载 tarball 并解压（不含 `.git`），用完即删 |
| `judge.py` | 判定核心：四种模式共用一套口径 |
| `run_all.py` | 批量跑某个模式 → `out/result_<mode>.jsonl` |
| `run_final.py` | 一键：full 模式 → 复制成 result_final → 评测 |
| `evaluate.py` | 调用官方评分脚本 |
| `app.py` | 图形界面（标准库 http.server） |
| `fuse.py` | 可选：多模式投票（消融实验用，不在主流程） |
| `check_traces.py` | 统计工具触发率、核对 sha 是否解析正确 |
| `docs/` | 中期汇报 PPT 及其生成脚本 |

## 图形界面

`python app.py` 后打开 http://127.0.0.1:7860

- 单条检测：从测试集选一条，或手动粘贴函数
- **批量上传 `.jsonl`**：官方格式（`idx / commit_url / target / func`）
- 批量跑测试集前 N 条，支持中途「停止」（当前条跑完即停）
- 实时显示分析过程（每次工具调用、检索到的案例）
- 结果可下载

界面与命令行共用同一套判定函数（`judge.judge_agent`），界面只负责输入与展示。

## 判定口径（judge.py）

模型必须先列出危险操作，再为每条找"守护校验"，**标签由代码合成**：

```python
first = ops[0]                                  # 只看最危险的一条
prediction = 0 if first["protected"] else 1
```

把"整体印象"变成"逐条核对"，同一 CVE 的两版才会给出不同结论。

## 五个关键工程决策

**① 关闭思考模式**

思考模式下 8000 max_tokens 全被 reasoning 吃掉，`content` 为空、`finish_reason=length`，
判定全部退化为 0。关闭后单条从 44 秒降到 7 秒，且能正常输出 JSON。

**② 仓库懒加载**

模型第一次调用仓库工具时才解析 sha、下载、解压；不调工具就一个字节都不下载。

实测触发率：不强制时 0.3%（1/300），启用强制触发规则后 8.7%（26/300）。
用工具的样本平均耗时 67.6 秒，不用的只要 2.3 秒——懒加载是成本生死线。

**③ 拒绝 .git**

仓库快照用 codeload 的 tar.gz，而不是 git clone。前者不带历史；
后者一条 `git log -p` 就能看到修复 diff，等于泄题。

**④ RAG 只给漏洞案例，且不做成工具**

两种做法都试过并否决：
- RAG 做成 `search_cases` 工具 → 模型频繁查、P-C 掉到 7%
- 成对给出漏洞版+修复版 → 模型倾向于"找剩余问题"，P-V 暴涨

最终用"预检索 + 注入上下文"，与 PPT 第 4 页的流程一致。

**⑤ 成对隔离**

`target` 不进 prompt；`label=1`（漏洞版）强制取**父提交**的快照，
`label=0`（修复版）取本提交。取反会让该对必错，且错误在日志里看不出来。

## 数据

官方材料位于 `../dataset/dataset/`：

- `test.jsonl`：300 条 = 150 对，字段 `idx / commit_url / target / func`。
  **`target` 就是 0/1 标签**，绝不能进 prompt。
- `knowledge.jsonl`：7578 条 = 3789 对，545 个项目。
  已核对：与测试集**零重叠**（0/300 函数、0/300 提交）。
- `evaluation.py`：官方评分。按「相邻两条」配对，不是按字段分组。

## 已知问题

1. **TensorFlow 仓库读不了**：测试集 46%（138 条）来自 TensorFlow，
   解压后路径超过 Windows 260 字符上限，`os.walk` 抛 `WinError 206`。
   本次跑中 26 个触发工具的样本里有 15 个因此失败（其中 14 个是 TensorFlow）。
   → 修法：解压到短路径或用 `\\?\` 长路径前缀。
2. BM25 是词袋检索，不理解语义：`memcpy` 与 `strcpy` 在它眼里是无关词。
3. 阳性率偏高：模型 61.7% 判为有洞，真实比例 50%，过度报警。
4. 约 4% 的样本返回的 JSON 不合法，代码会从文本里兜底提取 `prediction`。
5. 单次运行波动 ±5 对（σ≈5），A/B 等级不稳。
