# 事實清單（所有文件與腳本的單一來源）

README、說明頁、`docs/DEVELOPER.md` 與四支腳本用到的痕跡、時間與數值都以這份為準。要加一條事實，先加在這裡並附來源，再用到別處。

來源代號：
- **G** = MotherSphere 技術整理 <https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5>
- **W** = WormW 樣本分析 <https://github.com/WormW/nikke_malware_analysis>
- **B** = 巴哈姆特整理文 <https://m.gamer.com.tw/forum/C.php?bsn=36390&snA=23304>（引用 NGA tid=47843502）
- **H** = HKEPC 報導（Instagram 轉貼，2026-11-04）
- **M** = 本 repo 作者在一台中毒的港澳台版電腦上實測（2026-11-04）
- **K** = 韓國玩家 햄찌（hamzzi）的檢查・清除工具 v3.8（2026-11-04，<https://x.com/choi_hamzzi>）。社群工具，不是樣本分析；只靠 K 的項目標「推測擴充」
- **N** = 社群流傳的「受影響遊戲清單」：4chan 匿名貼文經 NGA 轉貼（2026-11-03），以及一則中文群組公告截圖。都沒有樣本或紀錄佐證，只當作待查線索
- **M2** = 本 repo 作者在自己電腦上對三角洲 Garena 版啟動器的唯讀檢查（2026-11-04）
- **GM** = Gamemeca 報導 <https://www.gamemeca.com/en/view.php?gid=1782921>（2026-11-04，含 Level Infinite 公告與 Krafton 回應）
- **S** = PUBG: BATTLEGROUNDS 的 Steam 商店頁 <https://store.steampowered.com/app/578080/>（2026-11-04 讀取）
- **D** = 防毒誤報的網路回報：<https://itch.io/post/14240566>、<https://forum.squareline.io/t/microsoft-defender-claims-trojan-script-wacatac-b-ml-on-installation-file/2681>（使用者回報，非微軟官方文件）

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
| `analytics.insightjs.com`，或它的 HSTS 雜湊 `wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw=` | `%APPDATA%\nikke_launcher*\tbs_cache\` 裡的 `TransportSecurity`、`Network Persistent State` | 中毒（連過木馬本體下載網域；屬歷史紀錄） | K；雜湊 M 重算 |
| `insightjs`，或 `insightjs.com` / `insightjs.org` 的 HSTS 雜湊 `JeFWywdZy+3jPC93e3P7ACdJ8liQHB7rH+9VHn7kswg=` / `+EQMCXxbp1N4L3mxYGR66hSUD0cvdir6DDtJBLH3wPk=` | 同上 | 有接觸 | K；雜湊 M 重算 |
| 安裝位置：`url_protocol.reg` 與 `HKCU\Software\Classes\nikkelauncher(hmt)\DefaultIcon` 寫著 `nikke_launcher.exe` / `nikke_launcher_hmt.exe` 的路徑 | `%APPDATA%\nikke_launcher*\` | 用來找安裝資料夾，不是痕跡 | K, M |

M：leveldb 與 Code Cache 是二進位檔；`Select-String` 在實測機上搜不到 `k2f.agent.state`，用位元組比對才找到。

M：HSTS 雜湊是 Chromium 的算法：主機名稱轉成 DNS 線路格式（每段前面加長度、結尾補 0）再取 SHA-256、Base64。2026-11-04 重算三個網域，跟 K 的常數一致。港澳台版的執行檔叫 `nikke_launcher_hmt.exe`，K 的找法只比對 `nikke_launcher.exe`，會漏掉港澳台版。

## 第 2 階段痕跡（Chrome 常駐）

- 登錄檔：`HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32`。只有 HKCU 底下的是惡意；HKLM 同名項是 Windows 的 `wpc.dll` — G, B, H
- 檔案：`%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<64 碼十六進位>\platform_experience_helper.dll`；每台受害者各自編譯，雜湊不是共通指標 — G, B, H
- 殘留：Chrome Application 資料夾下的 `platform_experience_helper.dll.old`、`old-clsid.txt`、`service_util.dll` — G
- 移除順序：先刪 HKCU 登錄項 → 重開機 → 只刪 64 碼子資料夾，不刪整個 PlatformExperienceHelper — G, B, H
- 推測擴充（只有 K）：同一個 CLSID 在 32 位元登錄（`HKCU\Software\Classes\WOW6432Node\CLSID\...`）；Edge、Brave、Vivaldi、Chromium、Opera、Opera GX 的使用者資料夾下同樣的 `PlatformExperienceHelper\<64 碼>`。公開樣本只看到 Chrome。腳本照查，但排除 Google 或 Microsoft 有效簽章的 dll
- 載入 dll 的程序：G、B 寫 chrome.exe；腳本改成查所有程序（K 的做法），因為 COM 劫持會被任何建立那個 COM 類別的程式載入 — K（推論）

## 暫存痕跡

- `%TEMP%\k2f-bcreds*`、`k2f_screen_*.jpg` — G, B
- 這台電腦每個使用者的 TEMP 都要查，不只目前登入的使用者 — K

## 其他遊戲（未證實）

- 社群說法：PUBG、三角洲、王者榮耀國際版、暗區突圍、沙丘：覺醒、帝國時代 Mobile、黎明覺醒等 Level Infinite 發行的 PC 版也中了 — N（未證實）
- PUBG 的官方回應：報導中被牽連的是 **PUBG Mobile**；Krafton 表示 PUBG Mobile 只以手機遊戲營運、沒有官方 PC 版，與這次事件無關。Level Infinite 11-04 的公告只說 PC 啟動器的腳本檔可能被第三方竄改，沒有點名其他遊戲 — GM
- PUBG PC（Steam 版，PUBG: BATTLEGROUNDS）：發行商是 KRAFTON，不是 Level Infinite；商店頁沒有標示第三方啟動器，由 Steam 直接啟動，反作弊是 Krafton 自家的 KSS — S。因此它不經過這次被竄改的 Level Infinite 啟動器網頁資源，判定「應無關」— 推論；沒有實機樣本，作者沒有安裝來測
- 支持這說法的線索：被竄改的 `aegis-fix.min.js` 放在 `sg-gpts.playerinfinite.com/comm/assets/lib/`，路徑看起來是共用的；另外 3 個檔案有 2 個在 `nikke_launcher/` 路徑下 — G（路徑），推論
- 反證（只限一台電腦、一個版本）：三角洲 **Garena 版**啟動器（2026-08 安裝，最後開啟 2026-09-09，早於竄改開始的 09-27）的網頁內容全部來自 `launcher.jupiterlauncher.com` 和 Garena 網域，`debug.log`、`%APPDATA%\df_garena_launcher*` 都沒有出現 `playerinfinite`、`insightjs` 或 `k2f` — M2。這不能代表 Steam 版或國際版，也不能代表 09-27 之後的版本
- 三角洲 Garena 版的補充實測（2026-11-04）：啟動器程式檔裡唯一的 Level Infinite 字樣是登入元件中的 `www.levelinfinite.com`，整個安裝資料夾與 `%APPDATA%\df_garena_launcher*` 找不到 `sg-gpts`、`webassets.playerinfinite`、`aegis-fix`、`vue-bucket` — M2
- 無法驗證的部分：它當時載入網頁的 `launcher.jupiterlauncher.com` 在 2026-11-04 已查不到 DNS，所以無法比對目前的線上版本；作者在台灣不開 VPN 時只找得到 Garena 版，找不到三角洲 Steam 版，沒有樣本可測 — M2
- 腳本的做法：`Check-K2F.ps1` 也認得三角洲 Garena 版的資料夾結構（`launcher\service\debug.log`、`%APPDATA%\df_garena_launcher*`），並掃描所有含 `tbs_cache` 的 `%APPDATA%` 資料夾。用的痕跡和妮姬相同，前提是同一隻木馬；其他遊戲目前沒有任何公開樣本
- `Remediate-K2F.ps1`：妮姬的啟動器快取一律隔離；其他啟動器的快取只有找到 `insightjs` 或 `k2f.agent.state` 時才隔離

## 已撤回、不算痕跡

- `%TEMP%\onominan.tmp`：G 撤回，戰前就存在於其他程式
- `PlatformExperienceHelper` 資料夾本身：Chrome 正常元件
- `FETCH_LIST suc success`：FeedList 正常輸出
- HKLM 底下的同名 CLSID

## 防毒誤報

- 本 repo 的 ZIP 在作者電腦上用 Defender 掃描（含雲端偵測、加上「來自網際網路」標記後解壓再掃）沒有發現威脅，病毒碼 1.463.119.0 — M（2026-11-04）
- Defender 對剛出現、下載量少的壓縮檔或腳本，可能以機器學習判定報毒，名稱帶 `!ml`（例如 `Trojan:Script/Wacatac.B!ml`），常見誤報 — D
- 本工具會結束程式、改 hosts、加防火牆規則、刪登錄機碼並以 `-ExecutionPolicy Bypass` 執行，外觀接近惡意腳本；這是誤判的可能原因，未經微軟確認 — M（推論）

## 木馬會偷的東西

瀏覽器密碼與 Session Cookie（Chrome、Edge、Brave、Firefox 等）、NIKKE 帳密（啟動器儲存的）、SSH/GPG/age 金鑰、Git 憑證、環境變數、AI 工具與 MCP 設定及 API 金鑰（Claude Code、Gemini CLI、Cursor 等約 1,790 個路徑）、雲端/CI/套件庫權杖、28 種錢包擴充功能、螢幕截圖；可執行任意 shell 指令（19 種指令，含 `exec`）— G, W, H
