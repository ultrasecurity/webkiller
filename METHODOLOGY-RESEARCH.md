# WebKiller — پژوهشِ متدولوژیِ هانترها و نقشهٔ راه (پیش‌نویسِ برنامه‌ریزی)

> هدف: ببینیم هانترهای شناخته‌شدهٔ باگ‌بانتی واقعاً چطور کار می‌کنند (از دلِ بلاگ‌ها و
> ارائه‌هایشان)، آن را با کاری که WebKiller **امروز** انجام می‌دهد تطبیق دهیم، و
> متدولوژی‌های کاندیدِ افزودن را بیرون بکشیم — به‌عنوانِ **ورودیِ برنامه‌ریزی**، نه فهرستِ
> کارها. هیچ‌چیز اینجا هنوز پیاده‌سازی نشده است.

---

## ۱. روش
متدولوژی‌های عمومیِ مرجع را مرور کردم: *Bug Hunter's Methodology* از Jason Haddix
(نسخه‌های TBHM، هم recon و هم AppSec)، راهنمای reconِ NahamSec/Ben Sadeghipour (در HackerOne)،
فلسفهٔ ابزارسازیِ TomNomNom، نوشته‌های جامعهٔ «Methodology 2025/2026»، چرخش با favicon-hash،
و پست‌های recon-automationِ Detectify. منابع در انتها آمده‌اند.

## ۲. ستون‌فقراتِ مشترکِ متدولوژی (آن‌چه همه بر سرش توافق دارند)
هر هانترِ جدی تقریباً همین قیف را طی می‌کند؛ تفاوتشان در این است که **کجا پهن می‌شوند و
کجا عمیق**، و **کدام تکنیک‌ها را به هم زنجیر می‌کنند**. ستون‌فقرات:

1. **تعیینِ دامنه و گسترشِ دارایی‌ها («شناساییِ گسترده»)** — یک دامنه را به کلِ سطحِ حمله
   تبدیل کن: خریدها و شرکت‌های تابعه، بازه‌های **ASN → CIDR**، certificate transparency،
   **چرخش با favicon-hash** (`http.favicon.hash` در Shodan / Censys)، دارایی‌های ابری
   (باکت‌های S3/GCS/Azure)، و **دورکینگِ سازمانیِ GitHub** برای کد و سکرت.
2. **شمارشِ ساب‌دامین‌ها** — غیرفعال (subfinder، amass، crt.sh، github-subdomains) → فعال
   (massdns، shuffledns، dnsx) → **جایگشت/بروت** (dnsgen، altdns، gotator) → **بازگشتی**
   (بروت زیرِ الگوهایی که پیدا می‌کنی، مثلِ `*.dev.target`).
3. **پروبینگ و نگاشتِ هاستِ زنده** — httpx (status، title، tech، پورت‌های 80/443/8080/8443).
4. **کشفِ محتوا و اندپوینت** — تاریخی (gau/waybackurls، robots.txt و JSِ آرشیوی)، کراول
   (katana/gospider/hakrawler)، **بروتِ دایرکتوری به‌صورتِ بازگشتی** (ffuf/feroxbuster/dirsearch)،
   **تحلیلِ JS** (linkfinder/subjs → اندپوینت‌ها + سکرت‌ها)، مسیرهای API (kiterunner).
5. **کشفِ پارامتر** — arjun، paramspider (تاریخی)، ffuf.
6. **فینگرپرینت / نوعِ فناوری + نسخه** — استکِ فناوری، WAF، و **نسخهٔ سرویس‌ها** (`nmap -sV`)
   برای سرنخ‌های نسخه→CVE.
7. **تستِ آسیب‌پذیری** — دو سبک که موازی اجرا می‌شوند (رویکردِ «دو-چشمی»): (الف) **پهنا** —
   تستِ هر پارامتر/اندپوینت برای کلاس‌های رایج؛ (ب) **عمق/خلاقیت** — دنبال‌کردنِ دارایی‌های
   جالب (ساب‌دامینِ فراموش‌شده، پنلِ ادمین، کلیدِ لو‌رفته) و **زنجیرکردنِ** یافته‌ها.
8. **تریاژِ سرنخ‌ها پیش از تستِ فعال** — به سبکِ TomNomNom با **الگوهای gf** کاندیدها را
   per-class کوتاه کن (`gf xss|sqli|ssrf|lfi|redirect` → `qsreplace` → `kxss`/probe) تا
   هوشمندانه فاز بزنی، نه روی همه‌چیز.
9. **PoC و گزارش** — شواهدِ تکرارپذیر، شدت/CVSS، و راهِ رفع.
10. **شناساییِ مداوم / پایش** — recon را در طول زمان دوباره اجرا کن و **diff** بگیر
    (ساب‌دامین/اندپوینتِ جدید)؛ استدلالِ محوریِ Detectify این است که تازه‌ترین دارایی برنده است.

## ۳. آن‌چه WebKiller همین حالا پوشش می‌دهد ✅
WebKiller به‌طور تمیز روی فازهای **۲ تا ۷ و ۹** می‌نشیند، و یک ارکستریتورِ AI-agent هم دارد
که اغلبِ ابزارها ندارند.

| فازِ ستون‌فقرات | ماژول(های) امروزِ WebKiller |
|---|---|
| شمارشِ ساب‌دامین (غیرفعال/فعال) | `subdomains_passive`، `subdomains_active` (subfinder/dnsx/…) |
| پروبینگ | `probe` (httpx) |
| اسکنِ پورت | `portscan` (naabu، با fallbackِ nmap) — **فقط پورت‌های باز** |
| کراول + URLهای تاریخی | `urls` (katana + gau) |
| کشفِ محتوا | `content` (ffuf) |
| کشفِ پارامتر | `params` (arjun) |
| تحلیلِ JS | `jsrecon` (اندپوینت‌ها + سکرت‌ها) |
| فینگرپرینت / WAF | `fingerprint` (wafw00f + techِ httpx) |
| اسکرین‌شات | `screenshots` (gowitness) |
| تستِ آسیب‌پذیری (per-class) | `vuln_signal`/`vuln_confirm` (nuclei) + ۱۶ ماژولِ `*_confirm`، به‌علاوهٔ `authz_probe`، `bypass_403`، `secret_verify` |
| DNS OSINT | `osint_dns` |
| گزارش | گزارشِ AI + خروجیِ export |
| ارکستریشن | **پروفایل‌های classic** + **حالتِ AI agent** (انتخابِ گام‌ها و زنجیرکردن) |

## ۴. شکاف‌ها — تکنیک‌هایی که هانترها به آن‌ها تکیه می‌کنند و WebKiller ندارد
بر اساسِ فازی که به آن تعلق دارند، همراه با منبعی که آن را تثبیت می‌کند.

**الف. شناساییِ گسترده / گسترشِ دارایی‌ها (بزرگ‌ترین شکاف، بیشترین اهرم)**
- **شمارشِ ASN → CIDR** (amass intel / asnmap) — از یک شرکت به بازه‌های IPش برس. *(TBHM)*
- **چرخش با favicon-hash** (favfreak + Shodan/Censys) — دارایی‌های خواهر/پنهان را از روی هشِ
  آیکون پیدا کن. *(FavFreak/Intigriti)*
- **شمارشِ دارایی و باکتِ ابری** (cloud_enum، s3scanner) — استوریجِ افشاشده. *(Methodology-2025, NahamSec)*
- **دورکینگِ سازمانیِ GitHub + اسکنِ سکرت** (gitdorker/trufflehog روی کلِ سازمان، نه فقط JSِ
  خودِ هدف). *(NahamSec)*
- **استخراجِ TLS SAN / cert** برای دامنه‌های خواهر. *(Censys, chs.us)*

**ب. عمقِ شناسایی**
- **جایگشت/بروتِ ساب‌دامین** (dnsgen/altdns/gotator) و بروتِ **بازگشتی**. *(Methodology-2025)*
- **diffِ JSِ آرشیوی** + تاریخچهٔ robots.txt (فراتر از gauِ ساده). *(NahamSec)*
- **استخراجِ تاریخیِ پارامتر** (paramspider). *(chs.us)*

**ج. هوشمندیِ فینگرپرینت / نسخه**
- **تشخیصِ نسخهٔ سرویس** (`nmap -sV` روی پورت‌های بازِ naabu) و به‌دلخواه OS، که سرنخ‌های
  **نسخه→CVE** را تغذیه می‌کند — دقیقاً همان ایده‌ای که در گفت‌وگوی آخرمان مطرح شد. *(TBHM AppSec)*

**د. تریاژِ سرنخ (یک متدولوژی است، نه یک ابزار)**
- **اولویت‌بندی با الگوهای gf**: پیش از شلیکِ ماژول‌های confirm، کاندیدها را per-class کوتاه کن
  تا تست متمرکز باشد. WebKiller الان مستقیم از کشف به confirm می‌رود. *(TomNomNom)*

**ه. حالت‌های کاری / متدولوژی‌های آماده (preset)**
- WebKiller *پروفایل* دارد (quick/full/aggressive/…) اما **متدولوژی‌های نام‌دارِ هانتر** ندارد.
  هانترها یک *workflow* را متناسب با هدف انتخاب می‌کنند: «شناساییِ گسترده روی برنامهٔ تازه»،
  «تک‌اپِ عمیق»، «API-first»، «JS-recon عمیق»، «پایشِ مداوم».
- **شناساییِ مداوم + diff/پایش** (اسکنِ مجدد، هشدار روی دارایی‌های جدید) — غایب است؛ WebKiller
  تک‌شات است. *(Detectify)*

**و. سطحِ API و اپ‌های مدرن**
- **کشفِ مسیرِ API** (kiterunner)، فازِ schema-aware؛ GraphQL پوشش دارد (`graphql_confirm`) اما
  شمارشِ REST/OpenAPI ندارد.

## ۵. پیشنهاد — «متدولوژی‌های آمادهٔ (preset)» + چند ماژولِ تکنیکیِ تازه
دو لایه، تا بدونِ بازنویسیِ موتور، *متدولوژی* اضافه کنیم:

**لایهٔ ۱ — متدولوژی‌های آماده (ارزان، پرارزش).** پلی‌بوک‌های نام‌دارِ تازه روی همان ماشینِ
پروفایل/agentِ موجود، که هرکدام یک workflowِ شناخته‌شده را کد می‌کنند و ماژول‌های فعلی را
مرتب می‌کنند:
- **Wide Recon (Haddix)** — تمرکز روی گسترشِ دارایی، پهنا بر عمق.
- **Content-Discovery (NahamSec)** — کراول + تاریخی + بروتِ بازگشتی + اندپوینت‌های JS.
- **Deep AppSec** — تک‌اپ، همهٔ ماژول‌های confirm، زنجیرکردن (نگاشت به AI-agent + aggressive).
- **API-first**، **JS-recon عمیق**، **Monitor/diff**.
این‌ها بیشتر config + ترتیب + شکل‌دهیِ promptِ agent هستند — نه موتورِ تازه.

**لایهٔ ۲ — ماژول‌های تکنیکیِ تازه (فقط آن‌چه presetها لازم دارند).** به‌ترتیبِ اولویت:

| کاندید | فاز | ارزش | زحمت | منبع |
|---|---|---|---|---|
| `nmap -sV` تشخیصِ نسخهٔ سرویس (+ سرنخ‌های نسخه→CVE) | Fingerprint | بالا | متوسط | TBHM |
| چرخشِ favicon-hash (favfreak+Shodan) | Wide recon | بالا | کم–متوسط | FavFreak |
| ASN→CIDR (asnmap/amass intel) | Wide recon | بالا | متوسط | TBHM |
| دورکِ سازمانیِ GitHub + trufflehog | Wide recon | بالا | متوسط | NahamSec |
| لایهٔ تریاژِ سرنخ به سبکِ gf | پیش از confirm | متوسط–بالا | کم | TomNomNom |
| جایگشت/بازگشتیِ ساب‌دامین | عمقِ recon | متوسط | کم | Methodology-2025 |
| شمارشِ باکتِ ابری | Wide recon | متوسط | متوسط | NahamSec |
| شناساییِ مداوم + diff/monitor | حالت (mode) | بالا (بلندمدت) | زیاد | Detectify |
| مسیرهای APIِ Kiterunner | سطح | متوسط | متوسط | Methodology-2025 |

## ۶. منبعِ دومی که همین حالا داریم: کتابخانهٔ محلیِ skillها
این محیط یک کتابخانهٔ بزرگ از پلی‌بوک‌های هانتینگ را به‌شکلِ **skill** دارد — `bb-methodology`،
`bb-recon-methodology`، `recon-scope-triage`، `redteam-mindset`، و یک skillِ `hunt-*` برای
تقریباً هر کلاسِ آسیب‌پذیری (xss، sqli، ssrf، idor، ssti، oauth، jwt-crypto، race-condition،
graphql، …). این‌ها متدولوژی‌های کدشده‌ای هستند که می‌توانیم مستقیم از آن‌ها استخراج کنیم تا
(الف) presetهای بالا را اعتبارسنجی کنیم و (ب) چک‌های هر ماژولِ confirm را غنی‌تر کنیم. ارزشِ
یک پاسِ جداگانه را دارد.

## ۷. فرایندِ پیشنهادیِ برنامه‌ریزی (تا بی‌نظم نباشد)
1. **پرسونای هدف را انتخاب کن** — WebKiller برای *شناساییِ گسترده روی برنامه‌های تازه* است،
   *تک‌اپِ عمیق*، یا هر دو؟ همین تعیین می‌کند کدام presetها مهم‌اند.
2. **فهرستِ preset را قفل کن** (لایهٔ ۱) — ارزان است، اول بفرست؛ همین‌ها موتورِ فعلی را مثلِ
   چند متدولوژی جلوه می‌دهند.
3. **ماژول‌های لایهٔ ۲ را رتبه‌بندی کن** بر اساسِ presetهایی که لازمشان دارند؛ هرکدام را مثلِ
   یک ماژولِ استاندارد طراحی کن (ابزار از طریقِ زیرسیستمِ managed-tool + مسیرِ confirm/record).
4. **پر‌اهرم‌ترین را spike بزن** (favicon-hash یا `nmap -sV`) به‌عنوانِ مرجع، پیش از تعهد به بقیه.
5. **دربارهٔ شناساییِ مداوم جدا تصمیم بگیر** — این یک تغییرِ حالت است (storage + diff + زمان‌بندی)،
   بزرگ‌تر از یک ماژول.

## ۸. منابع
- [TBHM v4 Recon (PDF)](https://hadariel.pp.ua/aboutme/ethical-hacking/files/TBHMv4%20Recon.pdf) · [TBHM v4 (hacker101)](https://www.hacker101.com/conferences/hacktivitycon2020/tbhm) · [TBHM AppSec v1 notes](https://www.trickster.dev/post/notes-from-the-bug-hunters-methodology-application-analysis-v1)
- [NahamSec — How to: Recon and Content Discovery (HackerOne)](https://www.hackerone.com/blog/how-to-recon-and-content-discovery)
- [Bug Bounty Methodology 2025 (amrelsagaei, GitHub)](https://github.com/amrelsagaei/Bug-Bounty-Hunting-Methodology-2025)
- [A TomNomNom Recon Tools Primer (Daniel Miessler)](https://danielmiessler.com/blog/a-tomnomnom-tools-primer)
- [Weaponizing favicon.ico (FavFreak)](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) · [Shodan & Censys guide (Intigriti)](https://blog.intigriti.com/hacking-tools/complete-guide-to-finding-more-vulnerabilities-with-shodan-and-censys)
- [Determining your hacking targets with recon & automation (Detectify)](https://labs.detectify.com/2022/12/07/determining-your-hacking-targets-with-recon-and-automation/)
- [Building a one-shot recon script (ProjectDiscovery)](https://projectdiscovery.io/blog/building-one-shot-recon)
- [Recon for bug bounty: 8 tools (Intigriti)](https://www.intigriti.com/researchers/blog/hacking-tools/recon-for-bug-bounty-8-essential-tools-for-performing-effective-reconnaissance)
