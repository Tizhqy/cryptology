# Manuel AES-128 Algoritması ve Karşılaştırma Raporu

**Ders:** Güvenli Haberleşme / Kriptoloji  
**Kurum:** Karadeniz Teknik Üniversitesi - Of Teknoloji Fakültesi - Yazılım Mühendisliği Bölümü  
**Öğretim Üyesi:** Dr. Hakan AYDIN  
**Geliştirici:** Yusuf Tan DURMUŞ (Öğrenci No: 445841)  
**Branch:** `yusuf-tan-durmus`  
**Kaynak Kod:** [`experiments/manual_aes/yusuf_aes.py`](yusuf_aes.py)  
**Otomatik Testler:** [`tests/experiments/test_manual_aes.py`](../../tests/experiments/test_manual_aes.py)

---

## 1. Seçilen AES Parametreleri

AES (Advanced Encryption Standard - Rijndael), FIPS-197 standardına uygun olarak simetrik bir blok şifreleme algoritmasıdır. Bu çalışmada ödev isterlerine uygun olarak **AES-128** seçilmiş ve kütüphanesiz olarak manuel kodlanmıştır:

| Parametre | Değer | Açıklama |
| :--- | :--- | :--- |
| **Algoritma** | AES-128 | Standart simetrik blok şifreleyici |
| **Blok Boyutu ($N_b$)** | 128 bit (16 Bayt) | 4x4 State matrisi (sütun öncelikli) |
| **Anahtar Boyutu ($N_k$)** | 128 bit (16 Bayt) | 4 adet 32-bit kelime |
| **Round Sayısı ($N_r$)** | 10 Round | AES-128 standardı gereği |
| **Round Anahtarı Sayısı** | 11 Adet (176 Bayt) | Round 0 (başlangıç) + 10 round |
| **Sonlu Cisim** | $GF(2^8)$ | $m(x) = x^8 + x^4 + x^3 + x + 1$ (0x11B) |
| **Dolgulama (Padding)** | PKCS#7 | Blok boyutunu 16'nın katı yapmak için |
| **Çalışma Modları** | ECB ve CBC | CBC modunda 16 baytlık rastgele IV |

---

## 2. Matematiksel Temeller ve Kodlanan Adımlar

Algoritma hiçbir harici kütüphane (`cryptography`, `pycryptodome` vb.) kullanılmadan, saf Python ile sıfırdan aşağıdaki modüller halinde kodlanmıştır:

### 2.1. $GF(2^8)$ Galois Field Aritmetiği
- **İndirgenemez Polinom:** AES, $GF(2^8)$ üzerinde çalışır. Baytların 2 ($x$) ile çarpılması için `xtime(a)` fonksiyonu yazılmıştır. Bayt sola 1 bit kaydırılır; eğer 8. bit (0x80) aktifse, taşma indirgenemez polinom olan `0x1B` (`x^4 + x^3 + x + 1`) ile XOR'lanır.
- **Genel Çarpma (`gf_mul`):** MixColumns ve InvMixColumns katsayılarının doğrulanması için genel Galois Field çarpımı kodlanmıştır.

### 2.2. Rijndael S-Box ve Ters S-Box (`INV_S_BOX`)
- Doğrusal olmayan (non-linear) ikame tablosudur. Kriptografideki **karışıklık (confusion)** prensibini sağlar.
- Deşifreleme için `INV_S_BOX[S_BOX[b]] == b` özelliğini sağlayan ters S-Box matrisi tanımlanmıştır.

### 2.3. Anahtar Genişletme (`KeyExpansion`)
- 16 baytlık anahtardan 10 round için toplam 11 adet 4x4 round anahtarı üretilir (44 kelime).
- Her 4 kelimede bir `RotWord` (sola 1 bayt kaydırma) ve `SubWord` (S-Box dönüşümü) uygulanır ve tur sabiti `Rcon[i/4]` ile XOR'lanır.

### 2.4. Dört Temel Round Dönüşümü (Şifreleme)
1. **SubBytes:** State matrisindeki 16 baytın her biri `S_BOX` tablosundan karşılığı ile değiştirilir.
2. **ShiftRows:** Satırlar dairesel sola kaydırılır:
   - Satır 0: 0 kaydırma
   - Satır 1: 1 bayt sola kaydırma
   - Satır 2: 2 bayt sola kaydırma
   - Satır 3: 3 bayt sola kaydırma
3. **MixColumns:** Sütunlar, $GF(2^8)$ üzerinde sabit matrisle çarpılarak **yayılma (diffusion)** sağlanır. `xtime` optimizasyonuyla bit düzeyinde hesaplanır.
4. **AddRoundKey:** State matrisi o turun 16 baytlık anahtarıyla XOR'lanır.
> **Not:** 10. (son) turda standart gereği **MixColumns uygulanmaz**.

### 2.5. Ters Round Dönüşümleri (Deşifreleme)
Ters sıra ve ters işlemlerle şifre çözme gerçekleştirilir:
1. `AddRoundKey` (10. Round Anahtarı)
2. 9'dan 1'e turlar: `InvShiftRows` $\rightarrow$ `InvSubBytes` $\rightarrow$ `AddRoundKey` $\rightarrow$ `InvMixColumns`
3. 0. Tur (Final): `InvShiftRows` $\rightarrow$ `InvSubBytes` $\rightarrow$ `AddRoundKey` (0. Round Anahtarı)

### 2.6. PKCS#7 Dolgulama (Padding)
- Veri boyutu $L$ ise, $P = 16 - (L \pmod{16})$ bayt eklenir ve her eklenen baytın değeri $P$'dir.
- Veri tam 16'nın katı olsa bile, deşifrelemede veri kaybı ve belirsizliği önlemek için 16 baytlık `0x10` dolgu eklenir.

### 2.7. CBC (Cipher Block Chaining) Modu ve IV
- $C_0 = \text{Encrypt}(P_0 \oplus \text{IV})$
- $C_i = \text{Encrypt}(P_i \oplus C_{i-1})$
- IV (Initialization Vector), aynı açık metnin ağda her iletildiğinde tamamen farklı şifreli paketler üretmesini sağlar.

---

## 3. NIST FIPS-197 Resmi Test Vektörleri Doğrulaması

Uygulamanın doğruluğu, NIST standardında yer alan bilinen cevap testleri (Known Answer Tests - KAT) ile teyit edilmiştir:

### Vektör 1 (FIPS-197 Ek B):
- **Plaintext:** `00112233445566778899aabbccddeeff`
- **Anahtar:** `000102030405060708090a0b0c0d0e0f`
- **Manuel Çıktı:** `69c4e0d86a7b0430d8cdb78070b4c55a`
- **NIST Beklenen:** `69c4e0d86a7b0430d8cdb78070b4c55a`
- **Sonuç:** $\mathbf{\checkmark}$ %100 Uyuşuyor.

### Vektör 2 (FIPS-197 Ek C.1):
- **Plaintext:** `3243f6a8885a308d313198a2e0370734`
- **Anahtar:** `2b7e151628aed2a6abf7158809cf4f3c`
- **Manuel Çıktı:** `3925841d02dc09fbdc118597196a0b32`
- **NIST Beklenen:** `3925841d02dc09fbdc118597196a0b32`
- **Sonuç:** $\mathbf{\checkmark}$ %100 Uyuşuyor.

---

## 4. Kütüphaneli Sonuç ile Karşılaştırma (cryptography vs Manuel)

Aynı girdi metni ("*KTÜ Of Teknoloji Fakültesi Güvenli Haberleşme AES-128 Manuel Deneyi!*") ve aynı anahtar/IV değerleri kullanılarak hem `cryptography` kütüphanesine hem de manuel algoritmaya verilmiştir:

| Mod | Manuel AES Çıktısı (Hex) | Kütüphane Çıktısı (Hex) | Sonuç |
| :--- | :--- | :--- | :---: |
| **ECB** | `894dfe51d470779607ea3e26207a9cc9...` | `894dfe51d470779607ea3e26207a9cc9...` | **BİREBİR AYNI** |
| **CBC** | `4dc5e8c1cce345472385b65889a59b18...` | `4dc5e8c1cce345472385b65889a59b18...` | **BİREBİR AYNI** |

---

## 5. Farkların Nedenleri (Padding, Çalışma Modu, IV ve Hız)

Ödev isterlerinde belirtilen karşılaştırma ve nedenler:

1. **Dolgulama (Padding) Farkı:**
   - AES bir blok şifreleyicidir ve veriyi mutlaka 16 baytlık bloklar halinde işler.
   - Kütüphanelerde raw blok şifreleme yapılırken padding kullanıcıya bırakılabilir ya da PKCS#7 otomatik uygulanır. Manuel kodumuzda PKCS#7 standart olarak eklenmiş ve test edilmiştir.
2. **Çalışma Modu (ECB vs CBC vs GCM):**
   - **ECB (Electronic Codebook):** Bloklar bağımsız şifrelenir. Aynı veriler aynı şifreli blokları üretir (desen sızdırır). Wireshark paket analizinde tekrar eden bloklar fark edilebilir.
   - **CBC (Cipher Block Chaining):** Zincirleme yapı sayesinde desen sızdırmaz. Ancak kimlik doğrulama (integrity / authentication) sağlamaz.
   - **GCM (Galois/Counter Mode):** Üretim ortamında (production) ve ana haberleşme hattında tercih edilir; çünkü AEAD (Authenticated Encryption with Associated Data) sağlar (mesajın değiştirilmediğini GMAC etiketiyle garanti eder).
3. **Başlangıç Vektörü (IV - Initialization Vector):**
   - CBC modunda ilk blok için bir önceki şifreli blok olmadığından 16 baytlık rastgele IV zorunludur. IV gizli olmak zorunda değildir fakat tahmin edilemez olmalıdır. Ağ üzerinden açık metin olarak şifreli verinin başında iletilir.
4. **Hız ve Performans Farkı (Benchmark Analizi):**
   - 2.000 blok şifreleme ölçümünde:
     - **Manuel AES (Saf Python):** ~0.155 saniye (~0.20 MB/s)
     - **Kütüphane AES (C / OpenSSL):** ~0.004 saniye (~7.08 MB/s)
   - **Neden?**
     - Saf Python kodu, Python sanal makinesinde (bytecode interpreter) dinamik tip denetimleri ve nesne referanslarıyla çalışır.
     - `cryptography` kütüphanesi C ile derlenmiş olup doğrudan işlemcinin donanımsal **AES-NI (Advanced Encryption Standard New Instructions: `aesenc`, `aesenclast`)** assembly talimatlarını kullanır. Donanım seviyesinde tek bir CPU çevriminde round dönüşümleri tamamlanır.

---

## 6. Çalıştırma Talimatı

Kodu ve testleri çalıştırmak için:

```powershell
# Manuel AES etkileşimli demosu, NIST doğrulama ve benchmark
python experiments/manual_aes/yusuf_aes.py

# Otomatik test paketini çalıştırma
python -m pytest tests/experiments/test_manual_aes.py -v
```
