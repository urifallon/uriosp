# uriosp

CLI hỗ trợ vận hành OpenStack theo hướng **readonly-first**:
- Quản lý `clouds.yaml` theo profile (`/etc/uriosp/profile/*.yaml`)
- Session auth qua env (không lưu password vào file)
- Chế độ inventory có lọc theo **tokens / name / id**
- Lệnh `uriosp os` có **readonly guard** (chặn các verb có khả năng thay đổi tài nguyên)

---

## 1) Cài đặt & phân quyền

### Thêm user vào group `uriosp`
```bash
sudo usermod -aG uriosp "$USER"
newgrp uriosp
id | grep uriosp
````

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

### Nạp clouds.yaml vào profile và set active

```bash
sudo uriosp config <path/to/clouds.yaml>
```

Ví dụ:

```bash
sudo uriosp config duong.yaml
```

### Danh sách profile / chuyển profile

```bash
uriosp list
uriosp use <profile>
```

---

## 3) Session authentication (không lưu password)

```bash
eval "$(uriosp auth)"
```

* Password chỉ nằm trong **session env** (`URIOSP_OS_PASSWORD`)
* Mở terminal mới thì cần chạy lại `eval "$(uriosp auth)"`

---

## 4) Chạy OpenStack CLI qua uriosp (readonly-guarded)

Ví dụ lệnh an toàn:

```bash
uriosp os token issue
uriosp os server list --all-projects
```

> Nếu lệnh bị chặn: tức là verb bị coi là mutating (create/delete/set/attach/...) và tool đang readonly.

---

## 5) Inventory

### Liệt kê toàn bộ

```bash
uriosp inventory vms
uriosp inventory projects
```

### Lọc theo tokens (AND)

```bash
uriosp inventory vms my-vm 10.10
uriosp inventory projects admin Enabled
```

### Lọc theo name

```bash
uriosp inventory vms name <name>
uriosp inventory projects name <name>
```

### Lọc theo id (UUID hoặc partial)

```bash
uriosp inventory vms id <id>
uriosp inventory projects id <id>
```

---

## Quick start (tóm tắt)

```bash
sudo usermod -aG uriosp "$USER"
newgrp uriosp

sudo uriosp config duong.yaml
eval "$(uriosp auth)"

uriosp os token issue
uriosp inventory vms
uriosp inventory vms name my-vm
uriosp inventory vms id addadf10

uriosp inventory projects
uriosp inventory projects name admin
uriosp inventory projects id df20f3b2
```
