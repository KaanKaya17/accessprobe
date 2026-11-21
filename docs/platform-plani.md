# Diğer platformlar: Firebase, PocketBase, Appwrite

*Hazırlandığı tarih: 20 Kasım 2026. Supabase sürümü FitLog üzerinde doğrulandıktan sonra yazıldı.*

## Özet

| Platform | Pazar / sorun büyüklüğü | Rakip durumu | Bizim farkımız | Zorluk | Öncelik |
|---|---|---|---|---|---|
| **Firebase** | Çok büyük. Firewreck 2.0: 1,5M Android uygulamasının 11.126'sı açık, 1,43 milyar kayıt | Statik kural taraması + anonim GET (Perufitlife, 2 yıldız) | İki kullanıcılı kanıt, kendi kendini temizleme | Orta | **1** |
| **PocketBase** | Küçük ama indie/vibe-coding'de büyüyor. Boş kural = herkese açık | Admin şifresi isteyen metadata taraması + anonim GET | Admin şifresi gerekmez, iki kullanıcılı kanıt | Düşük | **2** |
| **Appwrite** | Orta | Server API key ile metadata taraması + anonim GET | İki kullanıcılı kanıt | Orta | **3** |

**Önemli bulgu:** Üç platformdaki rakiplerin hiçbiri test kullanıcısı açıp "B, A'nın verisini görebiliyor mu" diye denemiyor. Hepsi "kural dosyası şüpheli mi" ya da "anonim GET veri döndürüyor mu" diye bakıyor. Firewreck araştırmasında açık sayılan iki kalıptan biri **"giriş yapan herkes okuyabilir"** (`request.auth != null`). Bu da Supabase'teki `auth.role() = 'authenticated'` hatasının Firebase'deki karşılığı, yani bizim tam yakaladığımız şey. Google bu durumu "kasıtlı davranış" sayıp düzeltmiyor, dolayısıyla açık kapanmayacak ve araca ihtiyaç sürecek.

## Önce: çekirdeği adaptör yapısına ayırmak (davranış değişmeden)

Şu an `probes.js` doğrudan PostgREST çağrıları yapıyor. Her platformda aynı mantık işliyor:

```
iki kullanıcı aç → A kaynak oluşturur → B ve anonim: oku / değiştir / sahte oluştur / sil → temizle → rapor
```

Değişen sadece "kaynak nedir ve nasıl çağrılır" kısmı. Hedef arayüz şu:

```js
adapter = {
  discover(site | sourceDir)      // URL, anahtar, kaynak listesi
  createUser() / deleteUser(u)    // Firebase ve PocketBase kendi hesabını silebiliyor
  resources()                     // tablo / koleksiyon / RTDB yolu / bucket
  create(res, asUser, ownerValue) // A'nın test kaydı
  read / update / remove / forge  // B ve anonim saldırıları
  fixFor(finding)                 // SQL / rules / PocketBase kuralı
}
```

Mevcut 22 test bu refactor sırasında koruma görevi görecek. Hiçbiri değişmeden geçmeli.

## 1. Firebase (öncelik 1)

**Keşif**
- Web: bundle içindeki `firebaseConfig` (`apiKey: "AIza…"`, `projectId`, `databaseURL`, `storageBucket`).
- Android: kaynak klasördeki `google-services.json`. Firewreck de aynı bilgiyi APK kaynaklarından çıkarmıştı.
- Koleksiyonlar: `firestore.rules` içindeki `match /x/{id}` satırları ve koddaki `collection(db, "x")` ile `.collection("x")` çağrıları. Firestore istemciye koleksiyon listesi vermediği için bu kaynak taraması şart.

**Test kullanıcıları (Supabase'ten kolay)**
- `identitytoolkit.googleapis.com/v1/accounts:signUp?key=…`: Firebase e-posta doğrulamasını varsayılan olarak zorunlu tutmuyor. Anonim giriş açıksa e-posta bile gerekmiyor.
- `accounts:delete` ile her kullanıcı kendi hesabını silebiliyor. Bu sayede **geride hiç test kullanıcısı kalmaz**. Supabase'te bunu ancak `--cleanup-rpc` ile yapabiliyorduk.

**Testler**
| Test | İstek |
|---|---|
| A belge oluşturur | `POST …/documents/{koleksiyon}?documentId=rlsprobe-xxx`, sahip alanı = A.uid |
| B, A'nın belgesini okur | `GET …/documents/{koleksiyon}/rlsprobe-xxx` (B'nin token'ı ile) |
| B tüm koleksiyonu listeler | `:runQuery` ya da Firewreck'teki gibi `:runAggregationQuery` count. Sadece sayı alınır, veri okunmaz |
| B değiştirir / siler | `PATCH` / `DELETE` |
| B, A adına belge oluşturur | Sahip alanı A.uid olan bir `POST` |
| Kullanıcı alt koleksiyonları | `users/{A.uid}/…` yolunda aynı testler |
| Realtime Database | `{databaseURL}/.json?shallow=true` (anonim) ve `/users/{A.uid}.json?auth=<B token>` |
| Storage | `firebasestorage.googleapis.com/v0/b/{bucket}/o?name=…` yükle, B ile `alt=media` dene, anonim `?prefix=` listele |

**Riskler**
- Doğrulayıcı kurallar (`request.resource.data.keys().hasOnly([...])`) A'nın belgesini reddedebilir. Bu durumda yeni kullanıcı kontrolüne düşülür ve "test edilemedi" deriz, asla "geçti" demeyiz.
- Sahip alanının adı belli değil (`uid`, `userId`, `ownerId` olabilir). Kural dosyasında `request.auth.uid == resource.data.X` kalıbı aranır; bulunamazsa yaygın adlar sırayla denenir.
- **Test ortamı:** Docker gerekmeden Firebase Emulator Suite ile gerçek kural motoruna karşı test edilebilir (Java gerektirir). Bu, sahte Supabase'ten daha güvenilir bir test zemini.

## 2. PocketBase (öncelik 2)

- Kurallar düz metin. **Boş string = herkese açık**, `null` = sadece admin. Klasik hata `@request.auth.id != ""` kuralı, yani "giriş yapan herkes".
- Kayıt: `POST /api/collections/users/records`, giriş: `auth-with-password`.
- Şema ve kurallar: `pb_migrations/*.js` dosyalarından okunur. Bu, Supabase'teki migration okumanın karşılığı. Rakip burada **admin şifresi istiyor**, biz istemeyiz.
- Kendi kaydını silme kuralı genelde `id = @request.auth.id` olduğu için temizlik yapılabilir.
- PocketBase tek bir binary olduğu için gerçek örnek üzerinde CI testi kolay.

## 3. Appwrite (öncelik 3)

- İzinler rol tabanlı: `any`, `users`, `user:<id>`. Yaygın hatalar `read("users")` ve Document Security'nin kapalı olması.
- Koleksiyon ve izinler `appwrite.json` dosyasından okunur.
- **Sınırlama:** İstemci kendi hesabını silemiyor, sadece engelleyebiliyor (`PATCH /account/status`). Test kullanıcıları elle silinmeli. Bunu rapora açıkça yazacağız.

## Önerilen sıra

1. **Adaptör refactor'ü:** yaklaşık 1 gün, davranış değişmez, 22 test korur.
2. **Firebase Firestore:** keşif, iki kullanıcı ve belge testleri. Emulator testleriyle birlikte yaklaşık 3–4 gün.
3. Firebase RTDB ve Storage: yaklaşık 1–2 gün.
4. PocketBase: yaklaşık 2 gün.
5. Appwrite: yaklaşık 2–3 gün.

Her adım ayrı bir sürüm olarak çıkabilir: `0.2` Firebase, `0.3` PocketBase…

## Etik sınır (her platformda aynı)

- Sadece sahibi olunan uygulamalar test edilir. Onay sorusu, `--yes` ve hiçbir başkasının verisini yazdırmama kuralı değişmez.
- Sayımlar (Firewreck'in yaptığı gibi) veri okumadan kanıt sağlar. Raporda başka kullanıcıların içeriği asla gösterilmez.

## Kaynaklar

- [Firewreck 2.0 (MrBruh)](https://mrbruh.com/firewreck2)
- [Firewreck kalıbı analizi (Newly)](https://newly.app/security/firebase-security-rules-audit-firewreck)
- [300M mesaj sızıntısı (Hackread)](https://hackread.com/firebase-misconfiguration-chat-ask-ai-users-expose/)
- [Firebase security checklist](https://firebase.google.com/support/guides/security-checklist)
- [Firestore: insecure rules](https://firebase.google.com/docs/firestore/security/insecure-rules)
- [Firestore REST API](https://firebase.google.com/docs/firestore/use-rest-api)
- [Perufitlife/firebase-security-skill](https://github.com/Perufitlife/firebase-security-skill)
- [Perufitlife/pocketbase-security-skill](https://github.com/Perufitlife/pocketbase-security-skill)
- [Perufitlife/appwrite-security-skill](https://github.com/Perufitlife/appwrite-security-skill)
- [PocketBase API rules](https://pocketbase.io/docs/api-rules-and-filters/)
- [Appwrite permissions](https://appwrite.io/blog/post/appwrite-permissions)
