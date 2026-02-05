Dưới đây là **README đã cập nhật** theo đúng thay đổi bạn đang làm:

* Đổi “inventory” → **`list`** (chức năng liệt kê/lọc projects & vms).
* `uriosp list` **mặc định là list profiles**.
* Giữ nguyên readonly-first + session auth.
* Bổ sung filter cho `vms`: `name`, `id`, và **`vol <vol_id_or_part>`** (chỉ vol id, không vol name).
* Thêm phần **màu header** qua `URIOSP_TITLE_BG/FG`.

---

# uriosp

CLI hỗ trợ vận hành OpenStack theo hướng **readonly-first**:

* Quản lý `clouds.yaml` theo profile (`/etc/uriosp/profile/*.yaml`)
* Session auth qua env (**không lưu password** vào file)
* Lệnh `uriosp os` có **readonly guard** (chặn verb có khả năng mutate)
* Lệnh `uriosp list` hỗ trợ lọc theo **tokens / name / id**

  * riêng **VMS**: thêm lọc theo **`vol` (volume id)**

---

## 1) Cài đặt & phân quyền

### Thêm user vào group `uriosp`

```bash
sudo usermod -aG uriosp "$USER"
newgrp uriosp
id | grep uriosp
```

> Nếu chưa có group/layout, chạy bootstrap:

```bash
sudo groupadd -f uriosp
sudo mkdir -p /etc/uriosp/profile /var/log/uriosp-logs
sudo touch /etc/uriosp/active /var/log/uriosp-logs/uriosp.log
sudo chown -R root:uriosp /etc/uriosp /var/log/uriosp-logs
sudo chmod 0750 /etc/uriosp /etc/uriosp/profile
sudo chmod 0640 /etc/uriosp/active
sudo chmod 0770 /var/log/uriosp-logs
sudo chmod 0660 /var/log/uriosp-logs/uriosp.log
```

---

## 2) Cấu hình profile (clouds.yaml)

### Nạp `clouds.yaml` vào profile và set active

```bash
sudo uriosp config <path/to/clouds.yaml>
```

Ví dụ:

```bash
sudo uriosp config duong.yaml
```

### Danh sách profile / chuyển profile

```bash
uriosp list             # list profiles
uriosp use <profile>
```

---

## 3) Session authentication (không lưu password)

```bash
eval "$(uriosp auth)"
```

* Password chỉ nằm trong **session env**: `URIOSP_OS_PASSWORD`
* Mở terminal mới thì cần chạy lại `eval "$(uriosp auth)"`

---

## 4) Chạy OpenStack CLI qua uriosp (readonly-guarded)

Ví dụ lệnh an toàn:

```bash
uriosp os token issue
uriosp os server list --all-projects
```

> Nếu lệnh bị chặn: verb bị coi là mutating (create/delete/set/attach/...) và tool đang readonly.

---

## 5) List (projects / vms)

### 5.1 Liệt kê toàn bộ

```bash
uriosp list projects
uriosp list vms
```

### 5.2 Lọc theo tokens (AND)

```bash
uriosp list vms my-vm 10.10
uriosp list projects admin Enabled
```

### 5.3 Lọc theo name

```bash
uriosp list vms name <vm_name_substring>
uriosp list projects name <project_name_substring>
```

### 5.4 Lọc theo id (UUID hoặc partial)

```bash
uriosp list vms id <instance_uuid_or_part>
uriosp list projects id <project_uuid_or_part>
```

### 5.5 Lọc VMS theo volume id (`vol`)

> `vol` = volume **ID** hoặc partial ID. Không hỗ trợ volume name.

```bash
uriosp list vms vol <volume_uuid_or_part>
```

---

## 6) Tùy chọn màu header (optional)

Bạn có thể tô nền title line cho `list projects/vms` bằng ANSI color:

```bash
URIOSP_TITLE_BG=45 URIOSP_TITLE_FG=97 uriosp list vms
```

* `URIOSP_TITLE_BG`: mã màu nền (vd `45` = tím)
* `URIOSP_TITLE_FG`: mã màu chữ (vd `97` = trắng)
* Có thể tắt màu:

```bash
URIOSP_COLOR=0 uriosp list vms
```

---

## Quick start

```bash
sudo usermod -aG uriosp "$USER"
newgrp uriosp

sudo uriosp config duong.yaml
eval "$(uriosp auth)"

uriosp os token issue

uriosp list
uriosp list vms
uriosp list vms name my-vm
uriosp list vms id addadf10
uriosp list vms vol 3a1b2c

uriosp list projects
uriosp list projects name admin
uriosp list projects id df20f3b2
```

