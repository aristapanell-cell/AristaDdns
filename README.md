<div align="center">

<p align="center">
  <img src="assets/logo/readme.png" alt="Arista DNS Hub" width="700">
</p>

# Arista DNS Hub

### سامانه جمع‌آوری، استخراج، تست و تحلیل DNS

<p>
سامانه‌ای برای جمع‌آوری، استخراج، بررسی، تحلیل، دسته‌بندی و انتشار DNSهای عمومی
</p>

<br>

<a href="https://t.me/aristapanel">
<img src="https://img.shields.io/badge/Telegram-229ED9?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram">
</a>

<a href="https://matrix.to/#/#arista:matrix.org">
<img src="https://img.shields.io/badge/Element-0DBD8B?style=for-the-badge&logo=element&logoColor=white" alt="Element">
</a>

</div>

---

## 🌐 لینک‌های پروژه

### 📦 جمع‌آوری کانفیگ‌ها

<a href="https://github.com/aristapanell-cell/AriataPanel">
<img src="https://img.shields.io/badge/GitHub-AriataPanel-181717?style=for-the-badge&logo=github&logoColor=white" alt="AriataPanel">
</a>

پروژه مربوط به جمع‌آوری، استخراج و پردازش کانفیگ‌ها.

---

### 🌍 وب Arista DNS

<div align="center">

<a href="http://aristapanell-cell.github.io/AristaDns/">
<img src="https://img.shields.io/badge/Arista%20DNS-GitHub%20Pages-181717?style=for-the-badge&logo=github&logoColor=white" alt="Arista DNS GitHub Pages">
</a>

<a href="https://aristadns.arista-panel.workers.dev/">
<img src="https://img.shields.io/badge/Arista%20DNS-Cloudflare%20Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Arista DNS Cloudflare">
</a>

</div>

---

## 📖 درباره پروژه

**Arista DNS Hub** یک سامانه برای جمع‌آوری و مدیریت DNSهای عمومی از منابع مختلف است.

هدف پروژه ایجاد یک پایگاه داده جامع، مرتب و قابل جست‌وجو از DNSهای مختلف است؛ به‌طوری که DNSهای استخراج‌شده پس از جمع‌آوری، بررسی، تحلیل، دسته‌بندی و در نهایت در رابط وب پروژه منتشر شوند.

فرآیند اصلی پروژه شامل:

**جمع‌آوری → استخراج → تشخیص → تحلیل → تست → حذف تکراری → دسته‌بندی → انتشار**

است.

---

## 🚀 قابلیت‌ها

- 🔎 جمع‌آوری DNS از منابع عمومی
- 📥 استخراج خودکار DNS
- 🌐 پشتیبانی از DNS over HTTPS
- 🔐 پشتیبانی از DNS over TLS
- 🌍 پشتیبانی از IPv4
- 🌎 پشتیبانی از IPv6
- 🔌 شناسایی DNSهای دارای پورت
- 🧩 شناسایی DNSهای بدون پورت
- 🏷️ دسته‌بندی DNSها
- 🛡️ شناسایی DNSهای AdBlock
- 👨‍👩‍👧 شناسایی DNSهای Family
- 🔒 شناسایی DNSهای Security
- 🦠 شناسایی DNSهای Malware
- 🔞 شناسایی Adult Filter
- 🚫 شناسایی DNSهای Unfiltered
- ⚡ تست و بررسی DNSها
- 📊 تولید آمار
- 🔍 جست‌وجوی DNS
- 🧹 حذف موارد تکراری
- 📦 تولید خروجی JSON
- 🔄 بروزرسانی خودکار داده‌ها
- 📱 رابط کاربری سازگار با موبایل
- 🖥️ رابط کاربری مدرن و شیشه‌ای
- ☁️ انتشار روی GitHub Pages
- ⚡ انتشار روی Cloudflare Workers

---

## 🔐 پروتکل‌های مورد بررسی

### DNS over HTTPS — DoH

نمونه:

    https://dns.example.com/dns-query

اطلاعات URL اصلی DNS حفظ می‌شود.

### DNS over TLS — DoT

نمونه بدون پورت:

    tls://dns.example.com

نمونه دارای پورت:

    tls://dns.example.com:853

در هر دو حالت مقدار اصلی منبع حفظ می‌شود.

---

## 🧪 تست و تحلیل

DNSهای استخراج‌شده می‌توانند در مراحل مختلف مورد بررسی قرار بگیرند.

موارد مورد بررسی می‌تواند شامل:

- معتبر بودن ساختار DNS
- معتبر بودن Host
- تشخیص IPv4
- تشخیص IPv6
- تشخیص DoH
- تشخیص DoT
- شناسایی پورت
- بررسی دسترسی‌پذیری
- بررسی Endpoint
- بررسی پاسخ DNS
- تحلیل وضعیت DNS
- دسته‌بندی DNS
- بررسی قابلیت استفاده

باشد.

---

## 🏷️ دسته‌بندی DNSها

DNSها بر اساس اطلاعات موجود در منابع در دسته‌های مختلف قرار می‌گیرند.

### دسته‌های عمومی

- Standard
- Private
- Unfiltered

### دسته‌های امنیتی

- Security
- Malware
- AdBlock

### دسته‌های خانوادگی

- Family
- Adult Filter

### پروتکل‌ها

- DoH
- DoT
- DNSCrypt

### نوع آدرس

- IPv4
- IPv6

---

## 🔄 بروزرسانی خودکار

داده‌های پروژه از منابع مشخص‌شده جمع‌آوری شده و پس از پردازش، خروجی جدید تولید می‌شود.

روند کلی:

    منابع عمومی
         ↓
    جمع‌آوری اطلاعات
         ↓
    استخراج DNS
         ↓
    تشخیص نوع و پروتکل
         ↓
    تحلیل اطلاعات
         ↓
    حذف Duplicate واقعی
         ↓
    تست و بررسی
         ↓
    دسته‌بندی
         ↓
    تولید JSON
         ↓
    انتشار در Arista DNS Hub

---

## 📦 ساختار داده

اطلاعات DNSها در قالب JSON ذخیره می‌شوند.

نمونه اطلاعات DoH:

    {
      "provider": "Example DNS",
      "doh_url": "https://dns.example.com/dns-query",
      "address": "dns.example.com",
      "name": "Example DNS",
      "source": "curl",
      "type": "DoH",
      "hostname": "dns.example.com",
      "path": "/dns-query",
      "protocol": "DoH"
    }

نمونه اطلاعات DoT:

    {
      "provider": "Example DNS",
      "address": "dns.example.com",
      "name": "Example DNS",
      "source": "curl",
      "type": "DoT",
      "hostname": "dns.example.com",
      "protocol": "DoT",
      "dot": "tls://dns.example.com:853"
    }

---

## 📊 آمار

Arista DNS اطلاعات آماری مختلفی از داده‌های جمع‌آوری‌شده ارائه می‌کند.

از جمله:

- تعداد کل DNSها
- تعداد IPv4
- تعداد IPv6
- تعداد DoH
- تعداد DoT
- تعداد AdBlock
- تعداد Family
- تعداد Security

آمار پس از بروزرسانی داده‌ها قابل مشاهده خواهد بود.

---

## 🔍 جست‌وجو

رابط وب پروژه امکان جست‌وجوی DNSها را فراهم می‌کند.

جست‌وجو می‌تواند بر اساس اطلاعات مختلفی مانند:

- آدرس
- Provider
- نام DNS
- Hostname
- URL
- نوع DNS
- پروتکل
- دسته‌بندی

انجام شود.

---

## 📱 رابط وب

رابط کاربری Arista DNS با تمرکز بر سادگی، سرعت و دسترسی مناسب طراحی شده است.

ویژگی‌های رابط:

- طراحی مدرن
- رابط شیشه‌ای
- نمایش کارت‌های DNS
- جست‌وجوی سریع
- فیلتر بر اساس نوع
- فیلتر بر اساس پروتکل
- فیلتر بر اساس دسته‌بندی
- نمایش آمار
- صفحه‌بندی
- کپی سریع DNS
- سازگاری با موبایل
- سازگاری با دسکتاپ

---

## 🌐 نسخه‌های وب

### GitHub Pages

نسخه میزبانی‌شده روی GitHub Pages:

<a href="http://aristapanell-cell.github.io/AristaDns/">
<img src="https://img.shields.io/badge/🌐%20مشاهده%20Arista%20DNS-GitHub%20Pages-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub Pages">
</a>

### Cloudflare Workers

نسخه میزبانی‌شده روی Cloudflare Workers:

<a href="https://aristadns.arista-panel.workers.dev/">
<img src="https://img.shields.io/badge/⚡%20مشاهده%20Arista%20DNS-Cloudflare%20Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Cloudflare Workers">
</a>

---

## 📦 پروژه مرتبط

### AriataPanel

بخش جمع‌آوری کانفیگ‌ها در پروژه AriataPanel قرار دارد.

<a href="https://github.com/aristapanell-cell/AriataPanel">
<img src="https://img.shields.io/badge/GitHub-AriataPanel-181717?style=for-the-badge&logo=github&logoColor=white" alt="AriataPanel">
</a>

---

## 🛠️ فناوری‌ها

پروژه با استفاده از فناوری‌ها و ابزارهای مختلف توسعه داده شده است:

- Python
- JavaScript
- HTML
- CSS
- JSON
- Requests
- BeautifulSoup
- GitHub Actions
- GitHub Pages
- Cloudflare Workers

---

## 📁 ساختار پروژه

    AristaDns/
    │
    ├── assets/
    │   └── logo/
    │       └── readme.png
    │
    ├── data/
    │   ├── dns.json
    │   └── stats.json
    │
    ├── parsers/
    │
    ├── scripts/
    │
    ├── index.html
    ├── style.css
    ├── script.js
    └── README.md

ساختار پروژه با توسعه قابلیت‌های جدید ممکن است تغییر کند.

---

## 🎯 هدف نهایی

هدف Arista DNS ایجاد یک مرجع جامع برای DNSهای عمومی و فراهم کردن دسترسی ساده و سریع به DNSهای مختلف است.

پروژه تلاش می‌کند تمام مراحل را به شکل خودکار انجام دهد:

**جمع‌آوری**

↓

**استخراج**

↓

**تشخیص**

↓

**تحلیل**

↓

**تست**

↓

**دسته‌بندی**

↓

**حذف موارد تکراری**

↓

**تولید داده**

↓

**انتشار**

---

## ⚠️ توجه

DNSهای موجود در این پروژه از منابع عمومی جمع‌آوری می‌شوند.

فعال بودن، سرعت و کیفیت DNSها ممکن است در طول زمان تغییر کند.

قرار گرفتن یک DNS در پایگاه داده به معنی تضمین دائمی عملکرد آن نیست.

---

## 👨‍💻 توسعه‌دهنده

<div align="center">

### توسعه‌دهنده: تیم آریستا❤️

اگر این پروژه برای شما مفید بود، با ⭐ Star کردن مخزن از توسعه و ادامه‌ی آن حمایت کنید. 🙏❤️

</div>
