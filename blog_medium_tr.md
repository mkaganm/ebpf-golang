# Go ve eBPF ile Ağ Güvenliğini

## Giriş

Siber güvenliğin modern çağında, ağ trafiğini izlemek ve güvenliğini sağlamak hayati önem taşımaktadır. eBPF (Extended Berkeley Packet Filter) teknolojisinin ortaya çıkışıyla, geliştiriciler artık ağ paketlerini filtrelemek, izlemek ve güvenlik politikalarını uygulamak için verimli, çekirdek seviyesinde programlar oluşturma yeteneğine sahipler. Go programlama dili ile birleştirildiğinde, eBPF daha da güçlü bir araç haline gelir ve sağlam ağ güvenliği çözümleri oluşturmak için yeni olanaklar sunar.

Bu blog yazısı, Go ve eBPF'yi kullanarak ağ güvenliğini artırmanın yollarını kapsamlı bir şekilde ele alır. Proje yapısını, teknik detayları, pratik kullanım senaryolarını ve geliştirme sırasında karşılaşılan zorlukları ve çıkarılan dersleri inceleyeceğiz.

---

## eBPF Nedir?

eBPF (Extended Berkeley Packet Filter), geliştiricilerin Linux çekirdeğinde sandboxed programlar çalıştırmasına olanak tanıyan devrim niteliğinde bir teknolojidir. Geleneksel çekirdek modüllerinin aksine, eBPF programları dinamik olarak yüklenebilir ve çekirdek yeniden derlenmeden çalıştırılabilir. Bu, eBPF'yi aşağıdaki görevler için ideal bir seçim haline getirir:

- **Ağ Paketi Filtreleme**: Ağ paketlerini çekirdek seviyesinde verimli bir şekilde filtreleyin ve işleyin.
- **Performans İzleme**: Sistem ve uygulama performansı hakkında ayrıntılı metrikler toplayın.
- **Güvenlik Politikalarının Uygulanması**: Güvenlik politikalarını doğrudan çekirdek içinde uygulayın.

### eBPF'nin Temel Özellikleri

- **Güvenlik**: eBPF programları, sistem kararlılığını tehlikeye atmadıklarından emin olmak için çekirdek tarafından doğrulanır.
- **Esneklik**: eBPF, ağdan gözlemlenebilirliğe kadar geniş bir uygulama yelpazesi için kullanılabilir.
- **Performans**: Doğrudan çekirdekte çalışarak, eBPF programları eşsiz bir verimlilik sağlar.

---

## Neden Go?

Go, basitlik ve verimlilik için tasarlanmış statik olarak yazılmış, derlenmiş bir dildir. Özellikleri şunları içerir:

- **Eşzamanlılık**: Go'nun goroutineleri ve kanalları, eşzamanlı uygulamalar oluşturmayı kolaylaştırır.
- **Performans**: Derlenmiş bir dil olarak Go, mükemmel çalışma zamanı performansı sunar.
- **Zengin Standart Kütüphane**: Go'nun standart kütüphanesi, ağ uygulamaları oluşturmak için sağlam destek içerir.

Go ve eBPF'yi birleştirerek, geliştiriciler çekirdek seviyesindeki programlarla sorunsuz bir şekilde etkileşim kuran kullanıcı alanı uygulamaları oluşturabilir ve gelişmiş işlevsellik ve performans sağlayabilir.

---

## Proje Genel Bakış

### Amaç

Bu projenin birincil amacı, gelen ağ paketlerini izlemek ve eBPF ve Go kullanarak güvenlik politikalarını uygulamaktır. Bu şunları içerir:

- Paketleri saymak ve belirli portları izlemek için bir eBPF programı yazmak.
- eBPF programıyla etkileşim kurmak ve verileri kaydetmek için bir Go uygulaması geliştirmek.
- Uygulamayı kolay dağıtım ve ölçeklenebilirlik için konteynerize etmek.

### Temel Özellikler

- **Paket Sayımı**: eBPF XDP programı kullanarak gelen ağ paketlerini sayın.
- **SSH Port İzleme**: Güvenlik analizi için SSH trafiğini algılayın ve kaydedin.
- **Docker Entegrasyonu**: Uygulamayı kolay dağıtım için konteynerize edilmiş bir ortamda çalıştırın.

---

## Proje Yapısı

```
ebpf-golang/
├── ebpf/
│   ├── packet_count.c          # eBPF XDP programı (C)
│   └── bpf/
│       └── bpf_helpers.h       # eBPF yardımcı fonksiyonları
├── main.go                     # Go uygulaması
├── main_port_monitor.go        # SSH port izleme uygulaması
├── Dockerfile                  # Docker yapılandırması
├── README.md                   # Dokümantasyon
└── LICENSE                     # MIT Lisansı
```

---

## Teknik Detaylar

### eBPF Programı

eBPF programı, Linux çekirdeğindeki XDP (eXpress Data Path) kancasına bağlanır. XDP, eBPF programlarının ağ arayüzüne ulaştıklarında paketleri kesmesine ve işlemesine olanak tanıyan yüksek performanslı bir paket işleme çerçevesidir.

#### Kod İncelemesi

```c
// packet_count.c
#include <linux/bpf.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") packet_count_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(long),
    .max_entries = 1,
};

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    int key = 0;
    long *value = bpf_map_lookup_elem(&packet_count_map, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
```

Bu program, paket sayısını depolamak için paylaşılan bir harita (`packet_count_map`) tanımlar. `count_packets` fonksiyonu, her gelen paket için sayacı artırır ve paketi `XDP_PASS` kullanarak bir sonraki katmana iletir.

### Go Uygulaması

Go uygulaması, derlenmiş bayt kodunu yükleyerek, ağ arayüzüne bağlayarak ve paylaşılan haritadan veri okuyarak eBPF programıyla etkileşim kurar.

#### Kod İncelemesi

```go
// main.go
package main

import (
    "fmt"
    "github.com/cilium/ebpf"
)

func main() {
    spec, err := ebpf.LoadCollectionSpec("packet_count.o")
    if err != nil {
        panic(err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        panic(err)
    }

    defer coll.Close()

    counter := coll.Maps["packet_count_map"]
    var value int64
    err = counter.Lookup(0, &value)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Paket Sayısı: %d\n", value)
}
```

Bu uygulama, Cilium eBPF kütüphanesini kullanarak eBPF programını yükler ve paylaşılan haritayla etkileşim kurar. `Lookup` yöntemi, paket sayısını alır ve ardından konsola yazdırır.

---

## Projeyi Çalıştırma

### Ön Koşullar

- Docker ve Docker Compose kurulu
- Linux ortamı (WSL2 veya Linux dağıtımı)

### Adımlar

1. Depoyu klonlayın:
   ```bash
   git clone <repository-url>
   cd ebpf-golang
   ```

2. Docker konteynerini oluşturun ve çalıştırın:
   ```bash
   docker-compose up --build
   ```

3. Paket sayısı ve SSH trafiği için günlükleri izleyin.

---

## eBPF Kullanım Senaryoları

### Ağ Güvenliği

eBPF'nin en parlak olduğu alanlardan biri ağ güvenliğidir. eBPF programlarını Linux çekirdeğindeki çeşitli kancalara bağlayarak, geliştiriciler ağ trafiği üzerinde eşsiz bir görünürlük ve kontrol elde edebilir. Örnekler:

- **Trafik Analizi**: Gelen ve giden paketleri gerçek zamanlı olarak inceleyerek, olağandışı trafik desenlerini veya yetkisiz erişim girişimlerini tespit edin.
- **Güvenlik Duvarı Uygulaması**: Karmaşık kurallara dayalı paketleri filtreleyen dinamik güvenlik duvarları oluşturun.
- **Saldırı Önleme Sistemleri (IPS)**: Paket yüklerini ve başlıklarını analiz ederek, kötü amaçlı trafiği kullanıcı alanı uygulamalarına ulaşmadan önce engelleyin.

### Performans İzleme

Performans izleme, eBPF'nin mükemmel olduğu bir diğer alandır. Sistem ve uygulama performansı hakkında ayrıntılı metrikler toplayarak, kaynak kullanımı optimize edilebilir ve genel verimlilik artırılabilir. Örnekler:

- **Sistem Tıkanıklıklarının Belirlenmesi**: Sistem çağrılarını, ağ olaylarını ve disk G/Ç işlemlerini izleyerek gecikmelere veya verimsizliklere neden olan alanları belirleyin.
- **Uygulama Profili Çıkarımı**: Uygulamaları çalışma zamanında profilleyerek, fonksiyon çağrı sıklığı, yürütme süresi ve kaynak tahsisi hakkında bilgi toplayın.
- **Ağ Verimliliği Optimizasyonu**: Paket akışını ve kuyruk uzunluklarını analiz ederek ağ verimliliğini optimize edin.

### Hata Ayıklama ve İzleme

Çekirdek seviyesindeki sorunları hata ayıklamak geleneksel olarak zorlu bir görev olmuştur, ancak eBPF bu süreci güçlü izleme yetenekleri sağlayarak basitleştirir. Örnekler:

- **Dinamik Enstrümantasyon**: Çalışan sistemlere kesinti veya yeniden derleme gerektirmeden prob ekleyin.
- **Olay Günlüğü**: Paket düşüşleri, bellek tahsis hataları veya CPU zamanlama kararları gibi çekirdek olaylarının ayrıntılı günlüklerini yakalayın.
- **Yığın İzleme**: Çökme veya performans sorunlarına yol açan olaylar için işlev çağrıları dizisini anlamak için yığın izleme oluşturun.

---

## Zorluklar ve Çıkarılan Dersler

### Zorluklar

- **Çekirdek Uyumluluğu**: eBPF programları, hedef çekirdek sürümüyle uyumlu olmalıdır.
- **Hata Ayıklama**: eBPF programlarını hata ayıklamak, çekirdek içinde çalışmaları nedeniyle zorlu olabilir.
- **Performans Ayarı**: eBPF programlarını yüksek performanslı ortamlar için optimize etmek dikkatli tasarım ve test gerektirir.

### Çıkarılan Dersler

- **Modüler Tasarım**: eBPF programını ve Go uygulamasını ayrı bileşenlere ayırmak, geliştirme ve hata ayıklamayı basitleştirir.
- **Konteynerizasyon**: Docker kullanmak, farklı ortamlar arasında tutarlı dağıtımı sağlar.
- **Dokümantasyon**: Kapsamlı dokümantasyon, işbirliği ve bakım için gereklidir.

---

## Sonuç

Go ve eBPF'yi birleştirmek, verimli ve güvenli ağ uygulamaları oluşturmak için güçlü bir çerçeve sağlar. Bu proje, bu teknolojilerin gerçek dünya senaryolarındaki potansiyelini göstermektedir. İster bir geliştirici olun ister bir güvenlik meraklısı, eBPF ve Go'yu keşfetmek yenilik için yeni fırsatlar açabilir.

Teşekkürler! Görüşlerinizi, sorularınızı veya deneyimlerinizi aşağıda paylaşabilirsiniz.
