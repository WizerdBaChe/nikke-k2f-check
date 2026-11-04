# 事實清單（所有文件與腳本的單一來源）

README、說明頁、`docs/DEVELOPER.md` 與四支腳本用到的痕跡、時間與數值都以這份為準。要加一條事實，先加在這裡並附來源，再用到別處。

來源代號：
- **G** = MotherSphere 技術整理 <https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5>
- **W** = WormW 樣本分析 <https://github.com/WormW/nikke_malware_analysis>
- **B** = 巴哈姆特整理文 <https://m.gamer.com.tw/forum/C.php?bsn=36390&snA=23304>（引用 NGA tid=47843502）
- **H** = HKEPC 報導（Instagram 轉貼，2026-11-04）
- **M** = 本 repo 作者在一台中毒的港澳台版電腦上實測（2026-11-04）

## 時間線

| 日期（UTC+8） | 事件 | 來源 |
|---|---|---|
| 2026-09-27 | 過期網域 insightjs.com 被重新註冊；同日 CDN 上的 JS 被竄改 | G, B |
| 2026-10-23 / 10-24 | 最早有人被裝上木馬（G/B 寫 10/24，H 寫 10/23） | G, B, H |
| 2026-11-04 01:04–01:21 | CDN 上 3 個檔案被換回 | B |
| 2026-11-04 02:31 後 | 攻擊者伺服器停止回應 | B |
| 2026-11-04 06:26 前 | 部分 CDN 節點仍發送被竄改的 FeedList | B |
| 2026-11-04 | 官方公告：已在 01:30 左右修復客戶端 | B |

## 被竄改的官方檔案與指紋（ETag）

| 檔案 | URL | 乾淨 ETag | 被竄改 ETag | 來源 |
|---|---|---|---|---|
| aegis-fix.min.js | https://sg-gpts.playerinfinite.com/comm/assets/lib/aegis-fix.min.js | 44c576454a5b0b4ed60e1a983aa4e782 | 50d1861152ea7f6875ffceb7d08445b5 | G |
| images.7fec4c32.js | https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/images.7fec4c32.js | 6e5f79cf9b7c364249f9de83ba7fa59e | 481e9b5ab8fb93406bf31980b53e0578 | G |
| FeedList.feb647c9.js | https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/FeedList.feb647c9.js | 04ee9800128396ba26f10ca70f170967 | b7d842200372ad0d9a84ef4cc8511311 | G |
| vue-bucket.min.js | https://na-webassets.playerinfinite.com/comm/assets/lib/vue-bucket.min.js | 63bc3a47b35b80a5d200dc5624d7126e | dd06875637a29cddd3bae2ba84142c78 | G |

M：2026-11-04 15:00 前後從台灣連線，4 個檔案都回傳乾淨 ETag。

## 網路痕跡

- 網域：`insightjs.com`、`analytics.insightjs.com`、`insightjs.org`（後者現由第三方放警告頁，仍列入封鎖）— G, W, H
- IP：`89.127.233.127`（攻擊者 VPS）、`89.126.250.172`（約用到 10/21）— G, H
- 木馬本體下載網址：`https://analytics.insightjs.com/comm/assets/insight.bundle` — G, W

## 第 1 階段痕跡（啟動器）

| 痕跡 | 位置 | 判定 | 來源 |
|---|---|---|---|
| `k2f_chan registered` + `adopted`/`resuming <uuid>` + `agent started as <電腦名稱>` | 安裝資料夾 `launcher\intl_service\debug.log` | 三者都有 = 中毒；只有第一行 = 大概率載入失敗 | G, B |
| `lua downloaded to log\tinyget\...` | 同上 | 下載過木馬 | G |
| `insight.bundle` | `launcher\log\tinyget\*.log` | 中毒 | G, B |
| `k2f*.lua`、或開頭為 LuaJIT 位元組 `1B 4C 4A 01` 的檔案 | `launcher\log\tinyget\` | 中毒 | G |
| `k2f.agent.state`（含 agent_id、c2s_counter） | `%APPDATA%\nikke_launcher*\tbs_cache\Local Storage\leveldb\*.log` | 中毒；刪遊戲也不會消失 | G, B |
| `insightjs` | `%APPDATA%\nikke_launcher*\tbs_cache\Code Cache\` | 有接觸 | B |
| 啟動器存的登入資料 `psd.dat`、`last_user.dat` | `%APPDATA%\nikke_launcher*\` | 木馬 creds 指令會讀 | G |

M：leveldb 與 Code Cache 是二進位檔；`Select-String` 在實測機上搜不到 `k2f.agent.state`，用位元組比對才找到。

## 第 2 階段痕跡（Chrome 常駐）

- 登錄檔：`HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32`。只有 HKCU 底下的是惡意；HKLM 同名項是 Windows 的 `wpc.dll` — G, B, H
- 檔案：`%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<64 碼十六進位>\platform_experience_helper.dll`；每台受害者各自編譯，雜湊不是共通指標 — G, B, H
- 殘留：Chrome Application 資料夾下的 `platform_experience_helper.dll.old`、`old-clsid.txt`、`service_util.dll` — G
- 移除順序：先刪 HKCU 登錄項 → 重開機 → 只刪 64 碼子資料夾，不刪整個 PlatformExperienceHelper — G, B, H

## 暫存痕跡

- `%TEMP%\k2f-bcreds*`、`k2f_screen_*.jpg` — G, B

## 已撤回、不算痕跡

- `%TEMP%\onominan.tmp`：G 撤回，戰前就存在於其他程式
- `PlatformExperienceHelper` 資料夾本身：Chrome 正常元件
- `FETCH_LIST suc success`：FeedList 正常輸出
- HKLM 底下的同名 CLSID

## 木馬會偷的東西

瀏覽器密碼與 Session Cookie（Chrome、Edge、Brave、Firefox 等）、NIKKE 帳密（啟動器儲存的）、SSH/GPG/age 金鑰、Git 憑證、環境變數、AI 工具與 MCP 設定及 API 金鑰（Claude Code、Gemini CLI、Cursor 等約 1,790 個路徑）、雲端/CI/套件庫權杖、28 種錢包擴充功能、螢幕截圖；可執行任意 shell 指令（19 種指令，含 `exec`）— G, W, H
