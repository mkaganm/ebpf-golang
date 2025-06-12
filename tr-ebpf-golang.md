# Go (Golang) ve eBPF ile Modern Linux Gözlemi: Detaylı Bir Rehber

## Giriş

Modern bulut altyapılarında, mikroservis mimarilerinde ve yüksek performanslı sistemlerde, sistem gözlemi ve ağ trafiği analizi kritik öneme sahiptir. Linux çekirdeğinin sunduğu eBPF (extended Berkeley Packet Filter) teknolojisi, sistemin derinliklerine inmeden, güvenli ve esnek bir şekilde gözlemleme ve analiz yapmamıza olanak tanır. Go (Golang) ise sistem programlama ve ağ uygulamaları için popüler, hızlı ve verimli bir dildir. Bu yazıda, Go ile eBPF’in nasıl entegre edileceğini, pratik örneklerle ve detaylı açıklamalarla ele alacağız. Ayrıca, gerçek dünyadan kullanım senaryoları, performans ipuçları ve ileri düzey eBPF tekniklerine de değineceğiz.

---

## 1. eBPF Nedir?

eBPF, Linux çekirdeğinde çalışan, güvenli ve yüksek performanslı mini programlar yazmamıza olanak tanıyan bir teknolojidir. eBPF programları, kernel’a yüklenir ve ağ paketleri, sistem çağrıları, tracepoint’ler gibi çeşitli olayları gözlemleyebilir veya manipüle edebilir. eBPF, klasik Berkeley Packet Filter’ın (BPF) modern ve genişletilmiş halidir.

### eBPF’in Temel Özellikleri
- **Performans:** Kernel-space’te çalıştığı için minimum overhead ile veri toplanır.
- **Güvenlik:** eBPF programları kernel tarafından doğrulanır, sistem kararlılığını bozmaz. Programlar yüklenmeden önce bir verifier tarafından analiz edilir.
- **Esneklik:** Ağ trafiği izleme, sistem çağrısı takibi, performans ölçümü, güvenlik, hata ayıklama ve daha fazlası için kullanılabilir.
- **Dinamiklik:** Çalışan bir sisteme, çekirdeği yeniden derlemeden yeni eBPF programları yüklenebilir.
- **Map ve Event Desteği:** Kullanıcı alanı ile kernel arasında veri paylaşımı için map’ler ve event’ler kullanılabilir.

### Kullanım Alanları
- Ağ paketlerini izleme ve filtreleme (firewall, DDoS koruması, trafik analizi)
- Sistem çağrısı (syscall) takibi (güvenlik, audit, performans)
- Performans ve latency ölçümleri (profiling, tracing, monitoring)
- Güvenlik ve saldırı tespiti (IDS/IPS, sandboxing)
- Dinamik gözlemleme ve hata ayıklama (debugging, observability)

#### eBPF’in Linux Ekosistemindeki Yeri
- **XDP (eXpress Data Path):** Ağ paketlerini kernel’in en erken aşamasında işlemek için kullanılır.
- **tc (Traffic Control):** Ağ trafiğini şekillendirmek ve filtrelemek için eBPF programları kullanılabilir.
- **kprobes/uprobes/tracepoints:** Kernel ve kullanıcı alanı fonksiyonlarını izlemek için eBPF ile hook’lar eklenebilir.

---

## 2. Go ile eBPF Kullanımı

Go, kullanıcı alanında (user space) eBPF programlarını yüklemek, yönetmek ve verileri okumak için idealdir. Kernel tarafında çalışan eBPF programları ise genellikle C dilinde yazılır. Go ile eBPF’in entegrasyonu için en popüler kütüphane [Cilium eBPF](https://github.com/cilium/ebpf)’dir. Bu kütüphane, eBPF objelerini yükleme, map’lerle çalışma, event dinleme ve hook’lara attach etme gibi işlemleri kolaylaştırır.

### Gerekli Araçlar ve Kurulum
- **Linux 4.8+ çekirdeği:** eBPF desteği için gereklidir. Daha yeni çekirdeklerde daha fazla eBPF özelliği bulunur.
- **Go:** https://golang.org/
- **Cilium eBPF Go paketi:** https://github.com/cilium/ebpf
- **LLVM/Clang:** eBPF bytecode derlemek için gereklidir.
- **bpftool:** eBPF objelerini incelemek ve yönetmek için kullanışlı bir araçtır.

Kurulum (PowerShell):

```powershell
go install github.com/cilium/ebpf/cmd/bpf2go@latest
go get github.com/cilium/ebpf
```

Ek olarak, Linux’ta aşağıdaki paketler de faydalı olabilir:

```bash
sudo apt-get install clang llvm libelf-dev gcc make bpftool linux-headers-$(uname -r)
```

---

## 3. eBPF Programlarının Temelleri

eBPF programları, kernel’in belirli noktalarına (hook) yüklenir ve burada çalışır. Programlar, C dilinde yazılır ve LLVM/Clang ile eBPF bytecode’a derlenir. Kullanıcı alanında ise Go ile bu programlar yüklenir, map’ler üzerinden veri okunur/yazılır ve event’ler dinlenir.

### eBPF Program Tipleri
- **XDP:** Ağ paketlerini kernel’in en erken aşamasında işler.
- **Socket Filter:** Belirli bir soket üzerinden geçen paketleri filtreler.
- **Kprobe/Uprobe:** Kernel veya kullanıcı alanı fonksiyonlarını izler.
- **Tracepoint:** Kernel event’lerini izler.
- **Cgroup/Sched:** Cgroup ve scheduler event’lerini izler.

### Map’ler ve Event’ler
- **Map:** Kernel ve kullanıcı alanı arasında veri paylaşımı sağlar. Array, hash, perf event gibi farklı tipleri vardır.
- **Perf Event:** Kernel’den kullanıcı alanına event göndermek için kullanılır.

---

## 4. Basit Bir eBPF Programı: Ağ Paketlerini Saymak

### 4.1. eBPF Programı (C ile Yazılır)

`packet_count.c`:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} packet_count SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    u32 key = 0;
    u64 *value = bpf_map_lookup_elem(&packet_count, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

Bu program, geçen her paketi sayar ve bir map’te saklar. XDP ile kernel’in en erken aşamasında çalışır, bu da minimum gecikme ve yüksek performans sağlar.

### 4.2. Go ile eBPF Programını Yüklemek ve Sonuçları Okumak

`bpf2go` ile Go binding’leri oluştur:

```powershell
bpf2go -cc clang.exe PacketCount packet_count.c -- -I"C:\path\to\linux-headers\include"
```

Go kodu ile eBPF programını yükle ve sayaç değerini oku:

```go
package main

import (
    "fmt"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "os"
    "os/signal"
    "syscall"
)

func main() {
    // eBPF objesini yükle
    objs := PacketCountObjects{}
    if err := LoadPacketCountObjects(&objs, nil); err != nil {
        panic(err)
    }
    defer objs.Close()

    // XDP hook’una attach et
    l, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.CountPackets,
        Interface: 2, // Ağ arayüzü index’i (ör: eth0 için 2)
    })
    if err != nil {
        panic(err)
    }
    defer l.Close()

    // Ctrl+C ile çıkış
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    fmt.Println("Paketler sayılıyor... Çıkmak için Ctrl+C")
    <-sig

    // Sayaç değerini oku
    var key uint32
    var value uint64
    if err := objs.PacketCount.Lookup(&key, &value); err != nil {
        panic(err)
    }
    fmt.Printf("Toplam paket: %d\n", value)
}
```

#### Kodun Açıklaması
- `PacketCountObjects` ve `LoadPacketCountObjects` fonksiyonları, bpf2go tarafından otomatik üretilir.
- `link.AttachXDP` ile eBPF programı belirli bir ağ arayüzüne yüklenir.
- Map üzerinden sayaç değeri okunur.

#### Dikkat Edilmesi Gerekenler
- Ağ arayüzü index’i doğru verilmelidir. `ip link` komutu ile arayüz index’lerini görebilirsiniz.
- eBPF programı yüklenirken root yetkisi gereklidir.
- Kernel ve Go tarafında kullanılan map tanımları birebir uyumlu olmalıdır.

---

## 5. C Kodu Yazmadan eBPF Kullanmak Mümkün mü?

Çoğu durumda, eBPF programları kernel tarafında C dilinde yazılır. Çünkü çekirdek ile doğrudan etkileşim ve derleyici (LLVM/Clang) gereklidir. Go ile doğrudan eBPF bytecode yazmak veya derlemek mümkün değildir. Ancak:

- Go ile sadece kullanıcı alanı işlemlerini (yükleme, veri okuma, event dinleme) yapabilirsin.
- bpftrace veya bcc gibi araçlarla, C kodu yazmadan yüksek seviyeli eBPF scriptleri yazabilirsin, fakat bunlar Go ile entegre çalışmaz.
- Rust gibi dillerde eBPF yazmak için projeler (ör. aya) vardır, fakat Go için native bir çözüm yoktur.

### bpftrace ile Yüksek Seviyeli eBPF

bpftrace, eBPF programlarını daha yüksek seviyede, C benzeri bir DSL ile yazmanıza olanak tanır. Örneğin:

```bpftrace
kprobe:do_sys_open {
    printf("%s %s\n", comm, str(arg1));
}
```

Bu script, her dosya açıldığında işlem adını ve dosya adını yazdırır. Ancak, bpftrace scriptlerini Go ile doğrudan entegre etmek mümkün değildir.

---

## 6. Gerçek Hayatta eBPF Kullanım Senaryoları

### 6.1. Ağ Güvenliği ve İzleme
- **Cilium:** Kubernetes ağ güvenliği ve gözlemi için eBPF kullanır. Ağ politikalarını kernel seviyesinde uygular.
- **Katran:** DDoS saldırılarını tespit etmek ve engellemek için XDP tabanlı eBPF programları kullanılır.
- **Örnek Kod:** Basit bir XDP eBPF programı ile gelen paketleri saymak:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} packet_count SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    u32 key = 0;
    u64 *value = bpf_map_lookup_elem(&packet_count, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

---

### 6.2. Güvenlik ve Olay Tespiti
- **Falco:** Güvenlik olaylarını tespit etmek için eBPF ile sistem çağrılarını izler.
- **Tracee:** Aqua Security tarafından geliştirilen, eBPF tabanlı bir runtime güvenlik ve izleme aracıdır.
- **Örnek Kod:** Bir dosya açma sistem çağrısını izleyen bpftrace scripti:

```bpftrace
kprobe:do_sys_open {
    printf("%s %s\n", comm, str(arg1));
}
```

---

### 6.3. Performans ve Gözlemleme
- **bcc, bpftrace:** Dinamik gözlemleme ve debugging araçlarıdır. Kernel ve uygulama seviyesinde detaylı analizler yapılabilir.
- **perf, sysdig:** eBPF ile sistem performansını ve olaylarını analiz eder.
- **Örnek Kod:** Bir fonksiyonun ne kadar sürdüğünü ölçen bpftrace scripti:

```bpftrace
uprobe:/usr/bin/myapp:myfunc
{
    @start[tid] = nsecs;
}
uretprobe:/usr/bin/myapp:myfunc
{
    printf("Süre: %d ns\n", nsecs - @start[tid]);
    delete(@start[tid]);
}
```

---

### 6.4. Diğer Kullanım Alanları
- **Sandboxing:** Uygulamaları izole etmek ve güvenliğini artırmak için eBPF kullanılabilir.
- **Custom Monitoring:** Kendi özel gözlemleme ve metrik toplama araçlarınızı geliştirebilirsiniz.
- **Örnek Kod:** Go ile eBPF map’ten sayaç okuma:

```go
var key uint32 = 0
var value uint64
if err := objs.PacketCount.Lookup(&key, &value); err == nil {
    fmt.Printf("Toplam paket: %d\n", value)
}
```

---

## 7. Performans, Güvenlik ve İleri Teknikler

### 7.1. Performans İpuçları
- eBPF programları mümkün olduğunca kısa ve hızlı olmalıdır. Kernel verifier, programların karmaşıklığını sınırlar.
- Map erişimlerini minimize edin.
- XDP ile paket işleme, geleneksel iptables veya netfilter’a göre çok daha hızlıdır.

### 7.2. Güvenlik
- eBPF programları yüklenmeden önce kernel verifier tarafından analiz edilir. Sonsuz döngü, bellek taşması gibi hatalara izin verilmez.
- eBPF programları sadece izin verilen alanlara erişebilir.

### 7.3. İleri Teknikler
- **Tail Calls:** eBPF programları arasında zincirleme çağrılar yapılabilir.
- **Helper Fonksiyonlar:** Kernel’in sunduğu yardımcı fonksiyonlar ile gelişmiş işlemler yapılabilir.
- **Ring Buffer:** Yüksek performanslı event aktarımı için kullanılabilir.

---

## 8. Kaynaklar ve İleri Okuma

- [Cilium eBPF Go Kütüphanesi](https://github.com/cilium/ebpf)
- [eBPF.io](https://ebpf.io/)
- [bpftrace](https://github.com/iovisor/bpftrace)
- [Linux eBPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)
- [Awesome eBPF](https://github.com/zoidbergwill/awesome-ebpf)
- [Brendan Gregg eBPF Kaynakları](http://www.brendangregg.com/ebpf.html)
- [Liz Rice: Learning eBPF](https://www.youtube.com/watch?v=Qh5kC6w7g1c)

---

## Sonuç

Go ve eBPF ile modern Linux sistemlerinde yüksek performanslı, güvenli ve esnek gözlemleme araçları geliştirmek mümkündür. eBPF’in gücüyle, sistemin derinliklerine inmeden, kernel seviyesinde veri toplayabilir ve analiz edebilirsiniz. Go ise bu programları kolayca yönetmenizi ve entegre etmenizi sağlar. eBPF ekosistemi hızla büyümekte ve yeni kullanım alanları ortaya çıkmaktadır. Siz de kendi gözlemleme, güvenlik veya performans analiz araçlarınızı geliştirmek için Go ve eBPF’i keşfetmeye başlayabilirsiniz. Sorularınız veya eklemek istedikleriniz için yorum bırakabilirsiniz!

## Örnek Proje: Go + eBPF ile Paket Sayacı

Bu bölümde, yukarıdaki kodların ve açıklamaların tamamı, `ebpf-golang` adlı örnek bir proje üzerinden gösterilmektedir. Proje yapısı:

- `ebpf/packet_count.c`: eBPF XDP programı (C)
- `main.go`: Go ile eBPF programını yükleyen ve sayaç okuyan uygulama
- `bpftrace-examples/`: bpftrace ile kullanılabilecek örnek scriptler
- `README.md`: Proje açıklaması ve kullanım talimatları

### 1. eBPF Programı (C)

`ebpf/packet_count.c`:
```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include "bpf/bpf_helpers.h"

// Paket sayısını tutacak eBPF map
struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

// XDP programı - her paket için çağrılır
SEC("xdp")
int count_packets(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *count;
    
    // Map'ten mevcut sayacı al
    count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        // Sayacı artır (atomik işlem)
        __sync_fetch_and_add(count, 1);
    }
    
    // Paketi geçir (XDP_PASS)
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### 2. Go ile eBPF Programını Yüklemek ve Sayaç Okumak

`main.go`:
```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest -go-package main packetcount ebpf/packet_count.c -- -I/usr/include -Iebpf

func main() {
	// eBPF objeleri yükle
	objs := packetcountObjects{}
	if err := loadPacketcountObjects(&objs, nil); err != nil {
		panic(fmt.Sprintf("eBPF objelerini yüklerken hata: %v", err))
	}
	defer objs.Close()

	// XDP programını ağ arayüzüne bağla
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: 2, // eth0 genellikle interface 2'dir
	})
	if err != nil {
		panic(fmt.Sprintf("XDP bağlarken hata: %v", err))
	}
	defer l.Close()

	// SIGINT/SIGTERM bekleme
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Paketler sayılıyor... Çıkmak için Ctrl+C")
	<-sig

	// Son paket sayısını al ve göster
	var key uint32 = 0
	var value uint64
	if err := objs.PacketCount.Lookup(&key, &value); err != nil {
		panic(fmt.Sprintf("Map'ten değer okurken hata: %v", err))
	}
	fmt.Printf("Toplam paket sayısı: %d\n", value)
}
```

### 3. bpftrace Scriptleri

`bpftrace-examples/README.md`:
```bpftrace
kprobe:do_sys_open {
    printf("%s %s\n", comm, str(arg1));
}

uprobe:/usr/bin/myapp:myfunc
{
    @start[tid] = nsecs;
}
uretprobe:/usr/bin/myapp:myfunc
{
    printf("Süre: %d ns\n", nsecs - @start[tid]);
    delete(@start[tid]);
}
```

### 4. Kurulum ve Çalıştırma

1. Gerekli araçları kurun: Go, clang, llvm, libelf-dev, bpftool
2. eBPF programını derleyin ve Go bindinglerini oluşturun:
   ```powershell
   go install github.com/cilium/ebpf/cmd/bpf2go@latest
   bpf2go -cc clang.exe PacketCount ebpf/packet_count.c -- -I"C:/path/to/linux-headers/include"
   ```
3. Go uygulamasını derleyin:
   ```powershell
   go build -o packet-counter main.go
   ```
4. Uygulamayı çalıştırın (root yetkisi gerekebilir):
   ```powershell
   .\packet-counter.exe
   ```

---

Artık blogdaki tüm örnekler ve açıklamalar, bu örnek proje üzerinden gösterilmektedir.

---

## 3. Pratik Örnek: Packet Counter

Bu bölümde, XDP kullanarak ağ paketlerini sayan basit ama etkili bir eBPF uygulaması oluşturacağız. Projemiz hem eBPF kernel kodu hem de Go user-space uygulamasını içerir.

### Proje Yapısı

```
ebpf-golang/
├── main.go                  # Go kullanıcı alanı uygulaması
├── ebpf/
│   ├── packet_count.c       # eBPF kernel programı
│   └── bpf/
│       └── bpf_helpers.h    # eBPF yardımcı fonksiyonları
├── Dockerfile               # Konteyner yapılandırması
├── docker-compose.yml       # Kolay dağıtım
├── go.mod                   # Go bağımlılıkları
└── README.md               # Proje dokümantasyonu
```

### eBPF Kernel Programı (C)

İlk olarak, XDP kullanarak paketleri sayacak olan eBPF programımızı yazalım:

```c
// ebpf/packet_count.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include "bpf/bpf_helpers.h"

// Paket sayısını tutacak eBPF map
struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

// XDP programı - her paket için çağrılır
SEC("xdp")
int count_packets(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *count;
    
    // Map'ten mevcut sayacı al
    count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        // Sayacı artır (atomik işlem)
        __sync_fetch_and_add(count, 1);
    }
    
    // Paketi geçir (XDP_PASS)
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### Go User-Space Uygulaması

Şimdi eBPF programını yükleyecek ve verileri okuyacak Go uygulamasını yazalım:

```go
// main.go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest -go-package main packetcount ebpf/packet_count.c -- -I/usr/include -Iebpf

func main() {
	// eBPF objeleri yükle
	objs := packetcountObjects{}
	if err := loadPacketcountObjects(&objs, nil); err != nil {
		panic(fmt.Sprintf("eBPF objelerini yüklerken hata: %v", err))
	}
	defer objs.Close()

	// XDP programını ağ arayüzüne bağla
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: 2, // eth0 genellikle interface 2'dir
	})
	if err != nil {
		panic(fmt.Sprintf("XDP bağlarken hata: %v", err))
	}
	defer l.Close()

	// SIGINT/SIGTERM bekleme
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Paketler sayılıyor... Çıkmak için Ctrl+C")
	<-sig

	// Son paket sayısını al ve göster
	var key uint32 = 0
	var value uint64
	if err := objs.PacketCount.Lookup(&key, &value); err != nil {
		panic(fmt.Sprintf("Map'ten değer okurken hata: %v", err))
	}
	fmt.Printf("Toplam paket sayısı: %d\n", value)
}
```

### Docker ile Dağıtım

Projemizi kolayca dağıtmak için Docker kullanıyoruz:

```dockerfile
# Dockerfile
FROM golang:1.24-bullseye as builder

WORKDIR /app

# eBPF geliştirme araçlarını yükle
RUN apt-get update && \
    apt-get install -y clang llvm libelf-dev gcc make bpftool linux-libc-dev && \
    ln -sfT /usr/include/x86_64-linux-gnu/asm /usr/include/asm

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# bpf2go ile Go bindings üret ve derle
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest && \
    $(go env GOPATH)/bin/bpf2go -go-package main packetcount ebpf/packet_count.c -- -I/usr/include -I./ebpf && \
    go build -o packet-counter .

# Runtime image
FROM debian:bullseye-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libelf1 bpftool iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/packet-counter ./

CMD ["/app/packet-counter"]
```

### Çalıştırma ve Test

Uygulamayı Docker Compose ile çalıştırabilirsiniz:

```yaml
# docker-compose.yml
version: '3.8'
services:
  ebpf-packet-counter:
    build: .
    privileged: true
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
```

Çalıştırma:
```bash
docker-compose up --build
```

### Başarılı Çalışma Sonucu

Uygulama başarıyla çalıştığında şu çıktıyı görürsünüz:
```
Paketler sayılıyor... Çıkmak için Ctrl+C
```

Bu, eBPF programının kernel'a yüklendiğini, XDP hook'una bağlandığını ve ağ trafiğini dinlemeye başladığını gösterir.

---

## 4. İleri Düzey eBPF Teknikleri

### BPF Maps Türleri ve Kullanımları

eBPF, farklı türlerde map'ler sunar:

```c
// Hash map - anahtar-değer çiftleri için
struct bpf_map_def SEC("maps") connection_tracker = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct flow_stats),
    .max_entries = 10000,
};

// Per-CPU array - CPU başına ayrı veriler
struct bpf_map_def SEC("maps") cpu_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 256,
};

// Ring buffer - user space'e event gönderimi
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 1024,
};
```

### Event-Driven Monitoring

```go
// Go tarafında event dinleme
func monitorEvents(eventMap *ebpf.Map) {
    reader, err := ringbuf.NewReader(eventMap)
    if err != nil {
        panic(err)
    }
    defer reader.Close()

    for {
        record, err := reader.Read()
        if err != nil {
            continue
        }
        
        // Event'i parse et ve işle
        processNetworkEvent(record.RawSample)
    }
}
```

### Performance Optimization

```c
// Inline fonksiyonlar - performans için kritik
static __always_inline int process_packet(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Bounds checking - verifier için gerekli
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;
    
    // Paket işleme...
    return XDP_PASS;
}
```

---

## 5. Gerçek Dünya Kullanım Senaryoları

### 1. DDoS Koruma Sistemi

```c
SEC("xdp")
int ddos_protection(struct xdp_md *ctx)
{
    // IP başına rate limiting
    struct iphdr *ip = get_ip_header(ctx);
    if (!ip) return XDP_PASS;
    
    __u32 src_ip = ip->saddr;
    __u64 *packet_count = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    
    if (packet_count && *packet_count > RATE_LIMIT_THRESHOLD) {
        return XDP_DROP; // Paketi düşür
    }
    
    // Rate counter'ı güncelle
    update_rate_counter(&src_ip);
    return XDP_PASS;
}
```

### 2. Application Performance Monitoring (APM)

```c
SEC("uprobe/http_request")
int trace_http_request(struct pt_regs *ctx)
{
    struct http_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    
    // HTTP request bilgilerini topla
    bpf_probe_read_user_str(event.url, sizeof(event.url), 
                           (void *)PT_REGS_PARM1(ctx));
    
    // User space'e event gönder
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}
```

### 3. Network Security Monitoring

```c
SEC("tc")
int network_security_monitor(struct __sk_buff *skb)
{
    struct security_event event = {};
    
    // Şüpheli ağ aktivitesi tespiti
    if (detect_suspicious_pattern(skb)) {
        event.alert_type = SUSPICIOUS_TRAFFIC;
        event.src_ip = get_src_ip(skb);
        event.dst_port = get_dst_port(skb);
        
        // Security event'i log'la
        bpf_ringbuf_output(&security_events, &event, sizeof(event), 0);
    }
    
    return TC_ACT_OK;
}
```

---

## 6. Troubleshooting ve Debug

### eBPF Program Debug

```bash
# eBPF programını yükleme durumunu kontrol et
bpftool prog list

# Map içeriğini görüntüle
bpftool map dump id <map_id>

# Program kaynak kodunu görüntüle
bpftool prog dump xlated id <prog_id>

# Verifier log'larını incele
echo 1 > /proc/sys/kernel/bpf_stats_enabled
bpftool prog show id <prog_id> --verbose
```

### Go Debug

```go
// Debug modunda daha detaylı hata mesajları
func loadProgram() {
    spec, err := ebpf.LoadCollectionSpec("program.o")
    if err != nil {
        log.Printf("eBPF spec yükleme hatası: %v", err)
        return
    }
    
    // Verifier log'larını etkinleştir
    coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
        Maps: ebpf.MapOptions{
            PinPath: "/sys/fs/bpf", // Map'leri pin'le
        },
    })
    if err != nil {
        log.Printf("Collection oluşturma hatası: %v", err)
        return
    }
}
```

### Common Issues

1. **Permission Denied:** `CAP_SYS_ADMIN` yetkisi gerekli
2. **Verifier Errors:** Bounds checking eksik veya infinite loop
3. **Map Not Found:** bpf2go ile generate edilen isimler farklı olabilir
4. **Kernel Compatibility:** Eski kernellerde tüm eBPF özellikleri mevcut değil

---

## 7. Performance İpuçları

### eBPF Program Optimization

```c
// 1. Inline fonksiyonlar kullan
static __always_inline bool is_tcp_packet(struct iphdr *ip) {
    return ip->protocol == IPPROTO_TCP;
}

// 2. Branch prediction hints
if (__builtin_expect(condition, 1)) {
    // Muhtemelen doğru olan yol
}

// 3. Per-CPU maps kullan - locking overhead'i azaltır
struct bpf_map_def SEC("maps") per_cpu_counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    // ...
};
```

### Go Performance

```go
// 1. Map batch operations kullan
keys := make([]uint32, batchSize)
values := make([]uint64, batchSize)
count, err := m.BatchLookup(keys, values, nil)

// 2. Memory pool kullan
var eventPool = sync.Pool{
    New: func() interface{} {
        return &NetworkEvent{}
    },
}

func processEvent() {
    event := eventPool.Get().(*NetworkEvent)
    defer eventPool.Put(event)
    // event'i işle...
}

// 3. Goroutine pool kullan
func startWorkers(numWorkers int) {
    for i := 0; i < numWorkers; i++ {
        go worker()
    }
}
```

---

## 8. Sonuç

eBPF ve Go kombinasyonu, modern sistem gözlemi, ağ güvenliği ve performans izleme için güçlü bir çözüm sunar. Bu yazıda ele aldığımız pratik örnek, gerçek dünyada kullanabileceğiniz bir temel oluşturur. 

### Önemli Faydalar:
- **Yüksek Performans:** Kernel-space'te minimal overhead
- **Güvenlik:** Verifier ile güvenli kod çalıştırma
- **Esneklik:** Dinamik program yükleme ve güncelleme
- **Gözlenebilirlik:** Sistem derinliklerine erişim

### Gelecek Adımlar:
1. **Cilium/eBPF** dokümantasyonunu inceleyin
2. **bpftrace** ile quick prototyping yapın
3. **Katran**, **Falco**, **Pixie** gibi production-ready eBPF projelerini araştırın
4. Kendi kullanım senaryolarınız için eBPF çözümleri geliştirin

eBPF ekosistemi hızla gelişiyor ve yeni özellikler ekleniyor. Bu teknolojinin potansiyelini keşfetmek için deneyimleme ve projeler geliştirme en iyi yöntemdir.