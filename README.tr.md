<h1 align="center">T3 · URL ve alan adı inceleme aracı</h1>
<p align="center">Bağlantıyı incele. Bulguları kaydet. Nelerin değiştiğini karşılaştır.</p>
<p align="center"><a href="README.md">English</a> · <a href="docs/TECHNICAL.md">Teknik referans</a></p>


T3; DNS, TLS, yönlendirme ve sınırlı HTML bulgularını tek kayıtta toplar. Bir bağlantıya güvenilirlik puanı vermez. Sertifika veya alan adı kaydı, site sahibinin niyetini kesin olarak kanıtlayamaz.

## Kurulum

Python 3.11 veya üstü gerekir. Repoyu klonladıktan sonra:

```sh
python -m venv .venv
```

PowerShell'de `.venv\Scripts\Activate.ps1`; Linux/macOS'ta `source .venv/bin/activate` ile ortamı açın.

```sh
python -m pip install -r requirements-audited.txt
python T3-Phishing-Detection/app.py
```

Tarayıcıda **http://127.0.0.1:5000** adresini açın. İşiniz bitince terminalde `Ctrl+C` kullanın.

## Kullanım

1. Bir alan adı veya URL yazın. Varsayılan pasif mod hedefe bağlanmadan URL'yi ayrıştırır.
2. Ağ bulguları için **Hedefe bağlan** seçeneğini işaretleyin. Her kontrolün durumunu ve ayrıntılarını inceleyin.
3. **JSON dışa aktar** ile kaydedin. **JSON raporu aç** ile daha sonra aynı kaydı hedefe yeniden bağlanmadan okuyun.
4. Sonraki kayıt açıkken **Önceki JSON'u seç** ile eski kaydı açın. Değişen kontroller ve inceleme kapsamı ayrı gösterilir. Yalnızca toplama zamanının değişmesi fark sayılmaz.

Dosyalar tarayıcı belleğinde işlenir; sunucuya yüklenmez. UTF-8 JSON, 4 MiB ve yapı sınırları uygulanır. Dosya özeti değişiklikleri izlemeye yarar; kaydın dürüstçe üretildiğini kanıtlamaz. HTML benzeri içerik metin olarak görüntülenir.

```sh
python t3.py inspect example.com --active --output before.json
python t3.py inspect example.com --active --output after.json
python t3.py compare before.json after.json
```

## Hangi sürüm ne yapar?

| Sürüm | Kapsam |
|---|---|
| Yerel Python uygulaması | URL, DNS, TLS, sınırlı HTTP/HTML; isteğe bağlı tehdit kaynağı |
| Statik sayfa | Yalnızca yerel URL ayrıştırması, kayıt açma ve karşılaştırma |

Statik sayfa bir çevrimiçi phishing tarayıcısı değildir. Python ve tarayıcı raporlarının şemaları farklıdır; birbirleriyle karşılaştırılmaz. JavaScript çalıştırma, indirme veya kullanıcı girişi senaryosu analizi yapılmaz.

Google Safe Browsing için ortam değişkeninde API anahtarı ve ayrıca açık kullanıcı seçimi gerekir. Sorgu parametreleri dahil URL Google'a gönderilir. Bir eşleşme kaynağın bulgusudur; eşleşme olmaması güvenlik kanıtı değildir.

[Geliştirme ve testler](README.md#development) · [Güvenlik sınırları](SECURITY.md) · [Yol haritası](docs/ROADMAP.md)
