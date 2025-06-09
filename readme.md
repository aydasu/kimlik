# Kimlik
Her projeye ayrı ayrı login, register, yetkilendirme zımbırtılarıyla uğraşmaktan gına geldiği için yazılmış minimailist ve Just Works TM OAuth sunucusu.

# Ne b*ka yarıyor?
* OAuth'un "Authorization Code" zımbırtısını yapıyor.
* Seri üretim bandında JWT craftlıyor.
* Kayıt kuyut temel ayak işi.
* API üzerinden de kullanıcının bilgilerini veriyor.

# Kurulum
Veritabanı oluştur.
```SQL
CREATE DATABASE kimlik;
CREATE USER 'kimlik'@'localhost' IDENTIFIED BY '1234';
GRANT ALL PRIVILEGES ON kimlik.* TO 'kimlik'@'localhost';

```
Sitenin /setup.php adresine git, veritabanı ve admin kurulumunu hallet.

# Entegrasyon
test_client/app.py'a bak.
config.php'den protokolü https yap.