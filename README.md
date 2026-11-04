# NIKKE PC 啟動器木馬檢查與處置工具

針對 2026 年 9 月底至 11/4 的 NIKKE PC 啟動器供應鏈攻擊（supply chain attack）：Level Infinite CDN 上 4 個 JS 被竄改，啟動器載入後下載遠端控制木馬（RAT，代號 K2F，C2 網域 `insightjs.com`）。

## 檔案

| 檔案 | 作用 |
|---|---|
| `Check-K2F.ps1` | 只讀偵測。分第 1 階段（啟動器）、第 2 階段（Chrome 常駐）判定，列出木馬活動時間線。 |
| `Remediate-K2F.ps1` | 處置。預設試跑（dry-run）只列出要做的事；加 `-Apply` 才動手。所有東西都是**移到隔離區**（`D:\archive\nikke-k2f-quarantine-<時間>`），不直接刪除，dll 會改名防止被載入。 |

## 用法（一定要在你自己開的 PowerShell 視窗跑）

Claude 桌面版裡的 shell 跑在 MSIX 沙箱（MSIX silo）中，`HKCU` 登錄檔和 `%LOCALAPPDATA%` 可能被虛擬化，看不到第 2 階段的痕跡。所以第 2 階段的判定只在你自己的視窗執行時才可信。

```powershell
powershell -ExecutionPolicy Bypass -File D:\AIWork\nikke-k2f-check\Check-K2F.ps1 -InstallPath D:\game\NIKKE_HMT
```

```powershell
powershell -ExecutionPolicy Bypass -File D:\AIWork\nikke-k2f-check\Remediate-K2F.ps1
```

確認試跑清單後，用「系統管理員」PowerShell 視窗執行（hosts 和防火牆封鎖需要管理員權限）：

```powershell
powershell -ExecutionPolicy Bypass -File D:\AIWork\nikke-k2f-check\Remediate-K2F.ps1 -Apply
```

第 3 步的 Chrome dll 若被鎖住：重新開機後再跑一次 `-Apply`。最後再跑一次 `Check-K2F.ps1` 確認。

## 判定標準

- **中毒（RED）**：debug.log 有 `k2f_chan registered` + `adopted/resuming` + `agent started as`；或 tinyget 下載紀錄有 `insight.bundle`；或 localStorage 有 `k2f.agent.state`；或 HKCU 有 `{E77CC89B-7401-4C04-8CED-149DB35ADD04}`；或 `PlatformExperienceHelper\<64 碼>\platform_experience_helper.dll` 不是 Google 簽章；或 `%TEMP%\k2f-bcreds*` / `k2f_screen*`。
- **有接觸（YELLOW）**：只有 `k2f_chan registered`、Code Cache 有 `insightjs`、DNS 快取有 insightjs。
- 已撤回、不算痕跡的：`onominan.tmp`、`PlatformExperienceHelper` 資料夾本身、`FETCH_LIST suc success`、HKLM 底下同名 CLSID（Windows 的 wpc.dll）。

## 與巴哈一鍵檢查的差異

巴哈文章的一鍵指令用 `Select-String` 搜 leveldb 和 Code Cache；這兩種是 Chromium 二進位檔，`Select-String` 會漏抓（本機實測：`k2f.agent.state` 明明在檔案裡，`Select-String` 搜不到）。本工具改用位元組比對（byte search），同時比 ASCII 與 UTF-16LE。

## 腳本做不到的事：換憑證

木馬會偷：瀏覽器存的密碼與登入狀態（cookie）、SSH/GPG 金鑰、Git 憑證、環境變數、AI 工具設定與 API key / OAuth token（Claude Code、Gemini CLI、Cursor、MCP 設定等）、雲端與套件庫 token、加密貨幣錢包、NIKKE 帳密、螢幕截圖，並可執行任意指令。

用**手機或另一台乾淨裝置**處理，順序由高價值到低：

1. Google 帳號（同時是 Chrome 密碼庫）：改密碼、到「安全性 → 你的裝置」登出所有工作階段、檢查兩步驟驗證。
2. Email、GitHub（撤銷 personal access token、`gh` 登入、SSH key）、Anthropic（Claude Code 重新登入、撤銷 API key）、Hugging Face token、Cloudflare（API token）、Discord / Telegram / LINE 的 bot token。
3. 本機所有 `.env`、`~/.ssh`、`~/.git-credentials` 裡的金鑰：一律當作外洩，到各服務後台重發。
4. Chrome 裡存過密碼的網站、網路銀行。
5. NIKKE（Level Infinite）帳號。
6. 加密貨幣：助記詞無法「改」，只能開新錢包把資產轉過去。

最保險的做法是重灌 Windows。

## 參考來源

- MotherSphere 技術整理：https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5
- WormW 樣本分析：https://github.com/WormW/nikke_malware_analysis
- 巴哈姆特整理：https://m.gamer.com.tw/forum/C.php?bsn=36390&snA=23304
