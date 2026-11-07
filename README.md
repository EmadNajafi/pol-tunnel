# pol (پل) — تانل معکوس به سبک Backhaul / Rathole / BackPack

یک تانل معکوس (reverse tunnel) با Go، بدون هیچ وابستگی خارجی (فقط کتابخانه استاندارد).
سرور ایران پورت‌های عمومی را باز می‌کند و سرور خارج **به سمت ایران وصل می‌شود**، پس خارج به هیچ پورت ورودی باز نیاز ندارد.

```
کاربر ──► ایران:443 ──[ tcp/tcpmux/ws/wsmux/wss/wssmux/spoof/spoofmux ]──► خارج ──► 127.0.0.1:443
          (server)                                                         (client)
```

---

## ۱. تحلیل سه پروژه

| | **Rathole** (Rust) | **Backhaul** (Go) | **BackPack** (Go) |
|---|---|---|---|
| مدل اتصال | یک control channel برای هر سرویس، data channel جدا برای هر اتصال | control + استخر (pool) اتصال آماده، یا mux | مثل Backhaul، به‌علاوه حالت direct (L3/GRE) |
| احراز هویت | چالش nonce + هش توکن (توکن روی سیم نمی‌رود) | توکن | توکن ۶۴ کاراکتری، سکوت در برابر توکن غلط |
| مالتی‌پلکس | ندارد (data channel از پیش ساخته‌شده) | smux (`tcpmux`, `wsmux`) | tcpmux/wsmux/QUIC |
| ترنسپورت‌ها | tcp, tls, noise, websocket | tcp, tcpmux, udp, ws, wsmux, wss, wssmux | tcp/mux/stealth(noise)/pck/kcp+fec/quic/ws/wss/icmp |
| ویژگی شاخص | بسیار سبک، کم مصرف | سینتکس پورت ساده (`443-600=1.1.1.1:5201`)، web panel | fallback بین ترنسپورت‌ها، چند آدرس پشتیبان، PROXY protocol |

**الگوی مشترک هر سه** (که pol هم دقیقاً همین را پیاده کرده):

1. **Handshake:** کلاینت (خارج) وصل می‌شود → سرور یک nonce می‌فرستد → کلاینت با HMAC توکن جواب می‌دهد.
2. **Control channel:** heartbeat و درخواست «اتصال بیشتر بساز».
3. **Data path:** یا (الف) استخر اتصال‌های آماده که هر کدام یک کاربر را حمل می‌کند (Rathole/Backhaul `tcp`)،
   یا (ب) چند اتصال ثابت که روی هر کدام stream‌های مجازی مالتی‌پلکس می‌شوند (`*mux`).
4. **Open header:** در ابتدای هر اتصال یا stream، سرور می‌گوید مقصد کجاست (`127.0.0.1:443`) و کلاینت به آن وصل می‌شود.

## ۲. پروتکل pol

```
Handshake (روی هر اتصال):
  S→C  "POL2" | sFlags[1] | sEphPub[32] | nonce[32]
  C→S  kind[1] | cFlags[1] | cEphPub[32] | HMAC-SHA256(token, "pol-c"|transcript)
  S→C  HMAC-SHA256(token, "pol-s"|transcript)        ← احراز هویت دوطرفه
  transcript = nonce | kind | sFlags | cFlags | sEphPub | cEphPub
  توکن غلط ⇒ سرور ساکت می‌ماند و اتصال را می‌بندد.
  اگر هر دو طرف encryption بخواهند ⇒ X25519 + HKDF ⇒ AES-256-GCM

kind: 1=control  2=data(pool)  3=mux session

Open header:  proto[1] (1=tcp 2=udp) | tlen[1] | target | slen[1] | src
Mux frame:    cmd[1] | streamID[4] | len[2] | payload
              SYN, DATA, FIN(half-close), RST, WND(flow control), PING, PONG
UDP روی stream:  len[2] | datagram
```

- **Flow control** در mux بر اساس credit است (هر stream حداکثر `mux_window` بایت بافر می‌کند)، پس یک کاربر کند بقیه را گیر نمی‌اندازد.
- **Half-close** درست پیاده شده (TCP FIN، FIN در mux و close-frame در WebSocket).
- اتصال‌های بیکار در استخر با ping زنده نگه داشته می‌شوند و اتصال‌های مرده حذف می‌شوند.
- روی ترنسپورت `ws` هر درخواست دیگری `404` می‌گیرد، پس پورت شبیه یک وب‌سرور معمولی است.

## ۳. نصب و اجرا

**نصب سریع با منوی تعاملی** (مثل Backhaul/BackPack — نصب، ساخت تونل، start/stop/status، همه با منو):

```bash
curl -fsSL https://raw.githubusercontent.com/EmadNajafi/pol-tunnel/main/install.sh | sudo bash
```

بعد از نصب، هر وقت خواستی منو را باز کنی فقط کافی است بزنی:

```bash
poltunnel
```

**یا دستی:** باینری‌های لینوکس (`pol-linux-amd64`، `pol-linux-arm64`) به‌همراه `SHA256SUMS` در [Releases](https://github.com/EmadNajafi/pol-tunnel/releases) هستند (اسکریپت نصب checksum را خودش بررسی می‌کند). یا خودتان build کنید:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o pol .
```

```bash
./pol -gen-token          # ساخت توکن تصادفی
./pol -c server.toml      # روی سرور ایران
./pol -c client.toml      # روی سرور خارج
```

### Connection Test — کدام تانل‌ها بین این دو سرور واقعاً کار می‌کنند

اینکه یک ترنسپورت بین دو سرور مشخص کار می‌کند یا نه، به **مسیر** بستگی دارد نه به برنامه: بعضی مسیرها هر اتصال جدید را بعد از چند پکت قطع می‌کنند، بعضی UDP را می‌بندند، بعضی TLS را ریست می‌کنند. تنها راه مطمئن این است که هر تانل را واقعاً روی مسیر اجرا کنی — Connection Test همین کار را می‌کند (مثل گزینه‌ی Connection Test در بک‌پک):

1. **روی سرور ایران** (منو ← `6) Connection Test` ← `Iran`، یا مستقیم):
   ```bash
   sudo pol -conntest                      # آدرس عمومی خودکار؛ یا: -conntest-host PUBLIC_IP
   ```
   برای **هر ترنسپورت** (tcp, tcpmux, ws, wsmux, wss, wssmux, spoof, spoofmux) و **تانل direct (L3)** یک موتور واقعی pol روی پورت آزاد بالا می‌آید و یک **لینک کوتاه** چاپ می‌شود، مثل `pol://t.AV2DoBhODzOj-SbrzyNqCmMAAQ`.
2. **روی سرور خارج** (منو ← `Kharej` ← لینک را paste کن، یا):
   ```bash
   sudo pol -conntest-join 'pol://t....'
   ```
   تنظیمات تست را از ایران می‌گیرد، سمت خودش همه‌ی تانل‌ها و یک سرویس echo را بالا می‌آورد.
3. سرور ایران از **همه‌ی تانل‌ها هم‌زمان** ترافیک رد می‌کند: **هر ثانیه یک echo به مدت یک دقیقه** روی همان اتصال (همان چیزی که کاربر واقعی می‌بیند)، بعد روی تانل‌هایی که همه را رساندند **سرعت دانلود و آپلود** (۴ stream، فقط بایت‌هایی که گیرنده تأیید کرده). اگر هر دو طرف root باشند، **جعل IP** هم در هر دو جهت (ایران→خارج و خارج→ایران) با منبع `10.10.10.10` بررسی می‌شود.
4. هر دو سرور جدول زنده و در پایان **حکم** را نشان می‌دهند: 🟢 **OK** (همه‌ی echoها رسید)، 🟡 **UNSTABLE** (افت داشت — با زمان اولین قطعی)، 🔴 **DOWN** (اصلاً بالا نیامد یا هیچ چیزی رد نکرد)، ⚪ **SKIPPED** (با دلیل). بعد لیست «Works steadily» با RTT و سرعت، توضیح هر خطا، و جدول **BEST SETTINGS** (ترنسپورت پیشنهادی، `mux_window` بر اساس سرعت×RTT، `heartbeat` و `keepalive_period` بر اساس RTT/افت).
5. **هیچ چیزی باقی نمی‌ماند**: موتورها، کانفیگ‌های موقت و اینترفیس‌های تست بعد از پایان (یا Ctrl+C) پاک می‌شوند.

```
VERDICT — Iran ⇄ kharej
RESULT   KIND      NAME         STATUS    ECHOES  PROGRESS

🟢       Reverse   TCP          OK        60/60   ▰▰▰▰▰▰▰▰ 100%
🟢       Reverse   TCP MUX      OK        60/60   ▰▰▰▰▰▰▰▰ 100%
🟡       Reverse   WS           UNSTABLE  54/60   ▰▰▰▰▰▰▰▱  90%
🔴       Reverse   SPOOF (UDP)  DOWN      0/60    ▱▱▱▱▱▱▱▱   0%
🔴       Direct    L3 / UDP     DOWN      0/60    ▱▱▱▱▱▱▱▱   0%
...
Notes:
🟡 Reverse WS: 54 of 60 echoes came back; first loss after 12s
🔴 Reverse SPOOF (UDP): never carried traffic in 1m0s — UDP looks blocked or throttled on this path
```

- لینک فقط آدرس coordinator و یک راز ۱۲ بایتی را دارد؛ توکن هر تانل از آن مشتق می‌شود و هر سؤال به coordinator با HMAC روی یک nonce تازه احراز می‌شود، پس کسی که لینک را ندارد نمی‌تواند در تست دخالت کند.
- تانل direct و چک جعل IP به **root روی لینوکس در هر دو سرور** نیاز دارند؛ بدون آن SKIPPED می‌شوند (`-conntest-direct=false` / `-conntest-spoof=false` برای حذف عمدی).
- پورت‌ها تصادفی‌اند (۲۰۰۰۰ تا ۳۲۰۰۰)؛ فایروال سرور ایران باید ورودی روی این بازه را اجازه دهد.

**لینک‌تست سریع بین دو سرور** (به سبک Link Test بک‌پک — تأخیر/jitter/loss + پیشنهاد):

```bash
# روی سروری که میزبان تانل می‌شود (ایران):
./pol -probe-listen :7000
# روی سرور دیگر (خارج):
./pol -probe IRAN_IP:7000
```
روی TCP و UDP **تأخیر، jitter و packet loss** را می‌سنجد، بررسی می‌کند دیتاسنتر اجازه‌ی **جعل IP** می‌دهد یا نه، و بر اساس کیفیت مسیر **ترنسپورت مناسب را پیشنهاد می‌دهد**:

```
── link test ───────────────────────────────
  TCP    ✓  latency 89.9 ms   jitter 2.1 ms   loss 0%
  UDP    ✓  latency 96.5 ms   jitter 2.3 ms   loss 0%
  SPOOF  ✗  datacenter filters forged source (BCP38)
────────────────────────────────────────────
recommendation:
  → tcpmux     (clean, low-latency route — simplest and efficient)
  + add  encryption = true  on both ends for an encrypted tunnel
```

نمونه کانفیگ‌ها در [examples/server.toml](examples/server.toml) و [examples/client.toml](examples/client.toml) هستند.
توکن و `transport` باید در هر دو طرف یکی باشند.

### سینتکس پورت‌ها (مثل Backhaul)

| ورودی | معنی |
|---|---|
| `"443"` | ایران :443 → خارج 127.0.0.1:443 |
| `"4000=5000"` | ایران :4000 → خارج :5000 |
| `"443-600"` | رنج، همان پورت‌ها |
| `"443-600:5201"` | کل رنج → 5201 |
| `"443=1.1.1.1:5201"` | به یک IP/پورت دلخواه (کلاینت وصل می‌شود) |
| `"127.0.0.2:443=5201"` | bind روی IP مشخص در ایران |

### سرویس systemd

```ini
# /etc/systemd/system/pol.service
[Unit]
Description=pol tunnel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/pol -c /etc/pol/config.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now pol
```

### پنل وضعیت
`web_port` فقط روی `127.0.0.1` باز می‌شود (`/` جدول، `/stats` خروجی JSON). برای دیدن از بیرون:
`ssh -L 2060:127.0.0.1:2060 root@IRAN_IP`

## ۴. انتخاب ترنسپورت

- **tcpmux**: پیش‌فرض خوب. تعداد اتصال‌ها بین دو سرور ثابت است و سربار handshake برای هر کاربر ندارد.
- **tcp**: هر کاربر یک اتصال واقعی دارد. برای ترافیک حجیم و تعداد اتصال کم مناسب است.
- **ws / wsmux**: برای عبور از CDN (مثلاً Cloudflare)؛ با `edge_ip` و دامنه در `remote_addr` / `tls_sni`.
- **wss / wssmux**: رمزنگاری TLS. بدون `tls_cert` یک گواهی self-signed ساخته می‌شود. با گواهی self-signed (`tls_insecure = true`) هویت سرور با TLS بررسی نمی‌شود؛ احراز هویت با توکن همچنان امن است، ولی کسی که وسط مسیر باشد می‌تواند لایه‌ی TLS را باز کند. برای محرمانگی کامل `encryption = true` را هم روشن کنید (کلیدش به توکن گره خورده است).
- **spoof / spoofmux**: روی UDP با لایه‌ی اطمینان‌پذیری ARQ (شبیه KCP)، با قابلیت **جعل IP مبدأ**. بخش ۷ را ببینید.

### رمزنگاری روی هر ترنسپورت (`encryption = true`)
با گذاشتن `encryption = true` روی **هر دو طرف**، بعد از دست‌دادن یک تبادل کلید **X25519** (forward secrecy، احرازشده با توکن) انجام می‌شود و کل تونل در **AES-256-GCM** پیچیده می‌شود — روی هر ترنسپورتی (tcp/ws/spoof/…). پس حتی `tcp` یا `spoof` هم رمز می‌شوند. ضد-replay هم دارد (شمارنده‌ی اکید روی stream، پنجره‌ی لغزان روی direct).

### چند آدرس پشتیبان و failover
کلاینت می‌تواند چند آدرس سرور داشته باشد و اگر یکی قطع بود خودکار سراغ بعدی برود:
```toml
remote_addr  = "1.2.3.4:443"
remote_addrs = ["5.6.7.8:443", "example.com:443"]
```

### PROXY protocol v2 (`proxy_protocol = true`)
با روشن‌کردنش روی کلاینت، IP واقعی کاربر در یک هدر PROXY v2 به سرویس مقصد فرستاده می‌شود (مثل nginx/traefik با `proxy_protocol`).

> ⚠️ بدون `encryption`، در `tcp`، `tcpmux`، `ws` و `wsmux` **داده رمز نمی‌شود** (فقط احراز هویت امن است، چون توکن روی سیم نمی‌رود). برای رمزنگاری از `wss` یا `wssmux` استفاده کنید.

## ۷. ترنسپورت spoof و جعل IP مبدأ

**ایده:** دو سرور خودتان به هم بسته می‌فرستند، ولی هر طرف می‌تواند IP مبدأِ بسته‌های خروجی‌اش را **جعل** کند. DPI/فیلترینگ به‌جای جریان واقعی `A↔B`، جریانی از یک IP بی‌خطر می‌بیند.

```
ایران (IP واقعی A) ──[ src=X جعلی, dst=B واقعی ]──► خارج (B)
خارج  (IP واقعی B) ──[ src=Y جعلی, dst=A واقعی ]──► ایران (A)
```

چون جواب هیچ‌وقت به IP جعلی نمی‌رود (بلکه به `peer_addr`/`remote_addr` واقعی)، این یک تانل **نقطه‌به‌نقطه بین دو سرور شما** است، نه ابزار ارسال به مقصد ثالث.

**چطور کار می‌کند:**
- چون TCP با مبدأ جعلی ممکن نیست (SYN-ACK گم می‌شود)، روی **UDP** کار می‌کند.
- UDP بسته گم می‌کند، پس یک لایه‌ی **ARQ شبیه KCP** روی آن نوشته شده: پنجره‌ی لغزان، ACK تجمعی + انتخابی، ارسال مجدد با RTO و fast-retransmit، و کنترل ازدحام ملایم (تا روی لینک پرخطا هم throughput حفظ شود). این لایه `net.Conn` قابل‌اعتماد می‌دهد، پس تمام منطق control/pool/mux بدون تغییر رویش اجرا می‌شود.
- دریافت با سوکت UDP معمولی است (مبدأ جعلی نادیده گرفته می‌شود)؛ فقط **ارسال** با raw socket و `IP_HDRINCL` هدر IP را با مبدأ جعلی می‌سازد.

**پیش‌نیازهای جعل (`spoof_source`):**
1. **لینوکس + root** (یا `CAP_NET_RAW`). روی ویندوز/مک کامپایل می‌شود ولی جعل کار نمی‌کند (فقط حالت UDP ساده).
2. **دیتاسنتری که BCP38 (فیلتر خروجی) نداشته باشد.** بیشتر ابرها (Hetzner، AWS، …) بسته‌ی جعلی را همان دم مبدأ دور می‌ریزند. معمولاً فقط سرورهای اختصاصی یا دیتاسنترهای خاص اجازه می‌دهند.
3. چون جواب به `peer_addr` می‌رود: اگر **کلاینت** مبدأ را جعل کند، سرور باید `peer_addr` (IP:پورت واقعی کلاینت) را داشته باشد.

> ⚠️ **بدون `spoof_source`** این ترنسپورت یک تانل UDP+ARQ معمولی و قابل‌اعتماد است و همه‌جا کار می‌کند. جعل اختیاری و فقط روی لینوکس/root/دیتاسنتر مناسب است.
> ⚠️ جعل IP تقریباً همیشه خلاف قوانین (ToS) ارائه‌دهنده است؛ فقط بین سرورهای خودتان و با آگاهی از ریسک مسدودشدن سرور استفاده کنید.

نمونه کانفیگ: [examples/spoof-server.toml](examples/spoof-server.toml) و [examples/spoof-client.toml](examples/spoof-client.toml).

```bash
# تست سریع بدون جعل (هرجا): transport=spoofmux و spoof_source خالی
# تست با جعل: روی دو سرور لینوکسی، با sudo، spoof_source را ست کنید
```

## ۸. حالت دایرکت (تونل L3 به سبک BackPack)

علاوه بر تونل معکوس، pol یک **حالت دایرکت** دارد: یک اینترفیس **TUN لایه‌۳** روی هر طرف که **کل بسته‌های IP** را می‌برد (نه فقط چند پورت). مثل حالت direct در BackPack.

- **رمزنگاری:** یک دست‌دادنِ شبیه Noise — تبادل کلید **X25519** (forward secrecy) با احراز هویت توسط توکن (HMAC)، بعد **AES-256-GCM** روی هر بسته. همه با کتابخانه‌ی استاندارد Go.
- **ضد-replay در دست‌دادن:** پیام INIT برچسب زمانی دارد (حداکثر ±۱۲۰ ثانیه اختلاف ساعت — ساعت سرورها را با NTP همگام نگه دارید) و سرور INITهای تکراری را رد می‌کند. کلیدهای جدید فقط بعد از رسیدن اولین بسته‌ی DATA معتبر جایگزین می‌شوند، پس یک INIT ضبط‌شده نمی‌تواند تونل را قطع کند یا مسیرش را عوض کند.
- **keepalive و اتصال مجدد:** هر دو طرف هر ۱۰ ثانیه یک بسته‌ی خالی رمزشده می‌فرستند؛ اگر کلاینت ۴۵ ثانیه چیزی نگیرد (مثلاً سرور ری‌استارت شده) دوباره دست می‌دهد.
- **حمل‌ونقل (carrier):** هر بسته‌ی IP داخل یک دیتاگرام رمزشده. هر طرف خودش انتخاب می‌کند بسته‌های خروجی‌اش چه شکلی باشند (`carrier`):
  | carrier | روی سیم | پیش‌نیاز |
  |---|---|---|
  | `udp` (پیش‌فرض) | UDP ساده | — |
  | `spoof` | UDP با **IP مبدأ جعلی** (`spoof_source`) | root + دیتاسنتر بدون BCP38 (با Link Test چک کنید) |

  اگر **کلاینت** مبدأ را جعل کند، سرور باید IP واقعی‌اش را در `spoof_peer_ip` داشته باشد (جواب‌ها به آن می‌رود، نه به IP جعلی).
  حامل‌های stream (`tcp`، `ws`، `kcp`، …) عمداً رد می‌شوند: بسته‌ی IP داخل یک لایه‌ی قابل‌اطمینان، زیر افت بسته سرعت را از بین می‌برد (دو لایه هم‌زمان retransmit می‌کنند).
- **چندمسیره (`paths = N`):** تونل روی N سوکت UDP روی پورت‌های پشت‌سرهم پخش می‌شود (سرور: `bind_addr` و پورت‌های بعدی). هر جریان (آدرس + پورت‌ها) همیشه روی یک مسیر می‌رود تا ترتیب بسته‌ها به‌هم نخورد، پس اگر مسیر روی هر جریان UDP محدودیت سرعت بگذارد، هر سوکت سهمیه‌ی خودش را می‌گیرد. `paths` باید **در هر دو طرف یکی** باشد و پورت‌های `bind ... bind+N-1` روی فایروال سرور باز باشند.
- **MTU خودکار (`auto_mtu = true`، پیش‌فرض):** بعد از برقراری تونل، هر طرف مسیر ارسال خودش را با بسته‌های پرشده‌ی احرازشده (و Don't Fragment) اندازه می‌گیرد، با جست‌وجوی دودویی بزرگ‌ترین اندازه‌ای که می‌رسد را پیدا می‌کند و MTU اینترفیس را روی آن می‌گذارد؛ هر ۳۰ دقیقه دوباره. اگر طرف مقابل جواب ندهد (نسخه‌ی قدیمی pol)، همان `mtu` تنظیم‌شده (پیش‌فرض ۱۴۰۰) می‌ماند. با `auto_mtu = false` فقط `mtu` استفاده می‌شود.
- فقط یک آدرس point-to-point اضافه می‌کند؛ **مسیر default را دست نمی‌زند**، پس به شبکه‌ی موجود سرور آسیب نمی‌زند.

**پیش‌نیاز:** لینوکس + **root** (برای `/dev/net/tun`). نمونه: [examples/direct-server.toml](examples/direct-server.toml) و [examples/direct-client.toml](examples/direct-client.toml).

```bash
sudo ./pol -c direct-server.toml   # روی یک سرور
sudo ./pol -c direct-client.toml   # روی سرور دیگر
# بعد از بالا آمدن: ping 10.200.0.1 / 10.200.0.2، یا هر سرویسی روی آن IPها
```

> ✅ **تست‌شده روی دو سرور واقعی ایران↔خارج:** تونل برقرار شد، ping هر دو جهت ۰٪ packet loss (~۸۵ms)، بسته‌های بزرگ بدون مشکل، و TCP (دانلود فایل با sha256 مطابق) از داخل تونل رمزنگاری‌شده عبور کرد — بدون اختلال در سرویس‌های موجود سرور.

## ۵. ساختار کد

| فایل | نقش |
|---|---|
| `proto.go` | handshake، open header، فریم UDP |
| `arq.go` | لایه‌ی اطمینان‌پذیری شبیه KCP روی UDP (پنجره، ACK، RTO، کنترل ازدحام) |
| `spoof.go` | ترنسپورت spoof: demux بر اساس connID، listener/dialer |
| `rawsend_linux.go` / `rawsend_other.go` | ارسال با IP مبدأ جعلی (raw socket، فقط لینوکس) |
| `direct.go` / `direct_crypto.go` | حالت دایرکت L3: موتور تونل، حامل‌ها (udp/spoof)، چندمسیره، دست‌دادن X25519 و AES-GCM |
| `direct_mtu.go` / `pmtu_linux.go` | MTU خودکار حالت دایرکت (probe احرازشده + جست‌وجوی دودویی) |
| `conntest.go` / `conntestboard.go` | Connection Test: اجرای واقعی همه‌ی تانل‌ها بین دو سرور، coordinator، echo/سرعت، جدول زنده و حکم |
| `probe.go` | Link Test: تأخیر/jitter/افت روی TCP و UDP، چک جعل IP، پیشنهاد ترنسپورت |
| `tun_linux.go` / `tun_other.go` | اینترفیس TUN لایه‌۳ (فقط لینوکس) |
| `mux.go` | مالتی‌پلکسر با flow control و half-close |
| `websocket.go` | پیاده‌سازی مینیمال RFC 6455 (کلاینت و سرور) |
| `transport.go` | listener/dialer برای tcp/ws/wss، TLS، `edge_ip` |
| `server.go` | سمت ایران: پورت‌ها، استخر، control، UDP |
| `client.go` | سمت خارج: استخر/mux، اتصال به مقصد |
| `ports.go` / `config.go` | سینتکس پورت و پارسر TOML |
| `pol_test.go` | تست end-to-end هر ۶ ترنسپورت (TCP + UDP + توکن غلط) |

```bash
go test -v ./...
```

## ۶. کارهایی که هنوز انجام نشده (در مقایسه با BackPack)

- ✅ ~~ترنسپورت UDP با اطمینان‌پذیری~~ و ✅ ~~جعل IP مبدأ~~ (بخش ۷) — انجام شد
- ✅ ~~حالت دایرکت L3 (TUN + X25519 + AES-GCM)~~ (بخش ۸) — انجام و روی سرور واقعی تست شد
- ✅ ~~رمزنگاری روی همه‌ی ترنسپورت‌ها (X25519 + AES-256-GCM)~~ و ✅ ~~ضد-replay~~ — انجام شد
- ✅ ~~چند آدرس پشتیبان + failover~~ و ✅ ~~PROXY protocol v2~~ — انجام شد
- FEC (تصحیح خطای رو به جلو) روی لایه‌ی ARQ، و QUIC، و تونل داخل ICMP (هرکدام یک کار بزرگ جدا)
- ممیزی امنیتی مستقل (رمزنگاری خانگی است؛ هرچند درست، بدون بازبینی بیرونی «تأییدشده» نیست)
- fallback خودکار بین ترنسپورت‌ها و چند آدرس پشتیبان
- PROXY protocol v2 برای رساندن IP واقعی کاربر به سرویس
