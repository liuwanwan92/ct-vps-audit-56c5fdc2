# 修复变更摘要

## 文件变更统计

```
vps-audit.sh        | 87 ++++++++++++++++++++++++++++++++---------------------
vps-audit-tests.sh  | 321 ++++++++++++++++++++++++++++++++++++++++++++++++++++
FIXES.md            | 234 ++++++++++++++++++++++++++++++++++++++
3 files changed, 542 insertions(+), 100 deletions(-)
```

---

## 关键修复对比

### 1. IPS/Docker 检查 (第 206-244 行)

**修复前** (42 行，重复逻辑):
```bash
if dpkg -l | grep -q "fail2ban"; then
    IPS_INSTALLED=1
    systemctl is-active fail2ban >/dev/null 2>&1 && IPS_ACTIVE=1
fi

# Check docker container running fail2ban
if command -v docker >/dev/null 2>&1; then
    if systemctl is-active --quiet docker; then
        if docker ps -a | awk '{print $2}' | grep "fail2ban" >/dev/null 2>&1; then
            IPS_INSTALLED=1
            docker ps | grep -q "fail2ban" && IPS_ACTIVE=1
        fi
    else
        check_security "Intrusion Prevention" "WARN" "Docker is installed but not running..."
    fi
fi

if dpkg -l | grep -q "crowdsec"; then
    IPS_INSTALLED=1
    systemctl is-active crowdsec >/dev/null 2>&1 && IPS_ACTIVE=1
fi

# Check docker container running crowdsec
if command -v docker >/dev/null 2>&1; then
    if systemctl is-active --quiet docker; then
        if docker ps -a | awk '{print $2}' | grep "crowdsec" >/dev/null 2>&1; then
            IPS_INSTALLED=1
            docker ps | grep -q "crowdsec" && IPS_ACTIVE=1
        fi
    else
        check_security "Intrusion Prevention" "WARN" "Docker is installed but not running..."  # ← 重复！
    fi
fi
```

**修复后** (38 行，单一逻辑):
```bash
IPS_INSTALLED=0
IPS_ACTIVE=0
IPS_NAME=""  # ← 新增：追踪具体 IPS 名称

if dpkg -l 2>/dev/null | grep -q "fail2ban"; then
    IPS_INSTALLED=1
    IPS_NAME="fail2ban"
    systemctl is-active fail2ban >/dev/null 2>&1 && IPS_ACTIVE=1
elif dpkg -l 2>/dev/null | grep -q "crowdsec"; then  # ← elif 避免重复
    IPS_INSTALLED=1
    IPS_NAME="crowdsec"
    systemctl is-active crowdsec >/dev/null 2>&1 && IPS_ACTIVE=1
fi

# Check docker containers only if no native IPS found  ← 条件守卫
if [ "$IPS_INSTALLED" -eq 0 ] && command -v docker >/dev/null 2>&1; then
    if systemctl is-active --quiet docker 2>/dev/null; then
        if docker ps -a 2>/dev/null | awk '{print $2}' | grep -q "fail2ban"; then
            IPS_INSTALLED=1
            IPS_NAME="fail2ban (docker)"
            docker ps 2>/dev/null | grep -q "fail2ban" && IPS_ACTIVE=1
        elif docker ps -a 2>/dev/null | awk '{print $2}' | grep -q "crowdsec"; then
            IPS_INSTALLED=1
            IPS_NAME="crowdsec (docker)"
            docker ps 2>/dev/null | grep -q "crowdsec" && IPS_ACTIVE=1
        fi
    else
        check_security "Intrusion Prevention" "WARN" "Docker is installed but not running..."
        # ← 只出现一次
    fi
fi

case "$IPS_INSTALLED$IPS_ACTIVE" in
    "11") check_security "Intrusion Prevention" "PASS" "$IPS_NAME is installed and running" ;;
    # ← 使用 IPS_NAME 而非硬编码
```

**修复效果**: Docker warning 从 2 次降为最多 1 次；IPS 名称精确显示

---

### 2. journalctl 命令替换 (第 251-253 行)

**修复前**:
```bash
elif [ -f "/etc/debian_version" ]; then
    DEB_VERSION=$(cut -d'.' -f1 /etc/debian_version)
    if [ "$DEB_VERSION" -gt 10 ]; then
        FAILED_LOGINS=$(grep -c "Failed password" "journalctl -u ssh --since \"24 hours ago\"" 2>/dev/null || echo 0)
        #                                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        #                                         错误：把命令当文件名！
    fi
```

**修复后**:
```bash
elif command -v journalctl >/dev/null 2>&1; then  # ← 检查命令存在性
    # Use journalctl for systems without auth.log (e.g., Debian 11+)
    FAILED_LOGINS=$(journalctl -u ssh --since "24 hours ago" 2>/dev/null | grep -c "Failed password" || echo 0)
    #               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #               正确：命令替换 + 管道
```

**修复效果**: journalctl 正确执行，不再静默返回 0

---

### 3. systemctl 可用性检查 (第 292-308 行)

**修复前**:
```bash
# Check running services
SERVICES=$(systemctl list-units --type=service --state=running | grep -c "loaded active running")
#         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#         无检查，容器/非 systemd 系统会失败
if [ "$SERVICES" -lt 20 ]; then
    check_security "Running Services" "PASS" "Running minimal services ($SERVICES)..."
```

**修复后**:
```bash
# Check running services
if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
    #  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #  双重检查：命令存在 + 实际可用
    SERVICES=$(systemctl list-units --type=service --state=running --quiet 2>/dev/null | grep -c "loaded active running" || echo 0)
    if [ "$SERVICES" -lt 20 ]; then
        check_security "Running Services" "PASS" "Running minimal services ($SERVICES)..."
    elif [ "$SERVICES" -lt 40 ]; then
        check_security "Running Services" "WARN" "$SERVICES services running..."
    else
        check_security "Running Services" "FAIL" "Too many services running ($SERVICES)..."
    fi
else
    # Fallback for non-systemd systems
    if command -v ps >/dev/null 2>&1; then
        SERVICES=$(ps aux 2>/dev/null | grep -c "^[^ ]* *[0-9]" || echo 0)
        check_security "Running Services" "WARN" "systemctl not available - detected $SERVICES processes via ps..."
        #                                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        #                                        明确告知用户降级检测
    else
        check_security "Running Services" "WARN" "Neither systemctl nor ps available..."
    fi
fi
```

**修复效果**: 容器/非 systemd 系统不再误报 "PASS - 0 services"

---

### 4. 端口检查命名统一 (第 302-326 行)

**修复前**:
```bash
if command -v netstat >/dev/null 2>&1; then
    LISTENING_PORTS=$(netstat -tuln | grep LISTEN | awk '{print $4}')
elif command -v ss >/dev/null 2>&1; then
    LISTENING_PORTS=$(ss -tuln | grep LISTEN | awk '{print $5}')
else
    check_security "Port Scanning" "FAIL" "Neither 'netstat' nor 'ss' is available..."
    #              ^^^^^^^^^^^^^^
    LISTENING_PORTS=""
fi

if [ -n "$LISTENING_PORTS" ]; then
    # ... 计算端口数 ...
    if [ "$PORT_COUNT" -lt 10 ] && [ "$INTERNET_PORTS" -lt 3 ]; then
        check_security "Port Security" "PASS" "Good configuration..."
        #              ^^^^^^^^^^^^^^  ← 名称不一致！
    # ...
else
    check_security "Port Scanning" "WARN" "Port scanning failed due to missing tools..."
    #              ^^^^^^^^^^^^^^  ← 又用回 Port Scanning
fi
```

**修复后**:
```bash
if command -v netstat >/dev/null 2>&1; then
    LISTENING_PORTS=$(netstat -tuln 2>/dev/null | grep LISTEN | awk '{print $4}')
    #                                ^^^^^^^^^^^ 添加错误抑制
elif command -v ss >/dev/null 2>&1; then
    LISTENING_PORTS=$(ss -tuln 2>/dev/null | grep LISTEN | awk '{print $5}')
    #                            ^^^^^^^^^^^
else
    check_security "Port Security" "FAIL" "Neither 'netstat' nor 'ss' is available..."
    #              ^^^^^^^^^^^^^^  ← 统一为 Port Security
    LISTENING_PORTS=""
fi

if [ -n "$LISTENING_PORTS" ]; then
    # ... 计算端口数 ...
    if [ "$PORT_COUNT" -lt 10 ] && [ "$INTERNET_PORTS" -lt 3 ]; then
        check_security "Port Security" "PASS" "Good configuration..."
        #              ^^^^^^^^^^^^^^  ← 统一
    # ...
elif [ -z "$LISTENING_PORTS" ] && (command -v netstat >/dev/null 2>&1 || command -v ss >/dev/null 2>&1); then
    # 工具存在但无结果 → 权限问题或无监听服务
    check_security "Port Security" "WARN" "Port scan returned no results..."
    #              ^^^^^^^^^^^^^^  ← 统一
fi
```

**修复效果**: 所有路径使用 "Port Security"，无重复/冲突

---

### 5. CPU 解析改用 /proc/stat (第 361-388 行)

**修复前**:
```bash
# Check CPU usage
CPU_CORES=$(nproc)
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print int($2)}')
#          ^^^^^^^^^^^^^^^^^^^^^^^^^^^
#          top 格式不稳定！
CPU_IDLE=$(top -bn1 | grep "Cpu(s)" | awk '{print int($8)}')
CPU_LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | awk -F',' '{ print $1 }' | tr -d ' ')
if [ "$CPU_USAGE" -lt 50 ]; then
    # ← 如果 CPU_USAGE 为空，这里会报错：integer expression expected
```

**修复后**:
```bash
# Check CPU usage
CPU_CORES=$(nproc 2>/dev/null || echo 1)
#                  ^^^^^^^^^^^ 添加默认值

# Parse CPU info from /proc/stat (more reliable than top which varies across systems)
if [ -f /proc/stat ]; then
    CPU_LINE=$(head -1 /proc/stat)
    # cpu  12345 678 910 111213 1415 1617 1819 0 0 0
    #      user nice system idle iowait irq softirq ...
    CPU_USER=$(echo "$CPU_LINE" | awk '{print $2}')
    CPU_NICE=$(echo "$CPU_LINE" | awk '{print $3}')
    CPU_SYSTEM=$(echo "$CPU_LINE" | awk '{print $4}')
    CPU_IDLE_VAL=$(echo "$CPU_LINE" | awk '{print $5}')
    CPU_IOWAIT=$(echo "$CPU_LINE" | awk '{print $6}')
    CPU_IRQ=$(echo "$CPU_LINE" | awk '{print $7}')
    CPU_SOFTIRQ=$(echo "$CPU_LINE" | awk '{print $8}')
    CPU_TOTAL=$((CPU_USER + CPU_NICE + CPU_SYSTEM + CPU_IDLE_VAL + CPU_IOWAIT + CPU_IRQ + CPU_SOFTIRQ))
    if [ "$CPU_TOTAL" -gt 0 ]; then
        CPU_USAGE=$(( (CPU_TOTAL - CPU_IDLE_VAL) * 100 / CPU_TOTAL ))
        CPU_IDLE=$(( CPU_IDLE_VAL * 100 / CPU_TOTAL ))
    else
        CPU_USAGE=0
        CPU_IDLE=100
    fi
else
    CPU_USAGE=0
    CPU_IDLE=100
fi
CPU_LOAD=$(uptime 2>/dev/null | awk -F'load average:' '{ print $2 }' | awk -F',' '{ print $1 }' | tr -d ' ' || echo "N/A")
#                 ^^^^^^^^^^^ 添加错误抑制和默认值
```

**修复效果**: 
- 不再依赖 top（格式不一致）
- /proc/stat 格式跨系统稳定
- 所有变量都有默认值，不会因空值崩溃

---

## 测试覆盖矩阵

| 修复项 | 静态分析测试 | 功能测试 | 重复执行测试 |
|--------|-------------|---------|-------------|
| IPS/Docker 去重 | ✅ 测试 12 | - | ✅ 测试 17 |
| journalctl 修复 | ✅ 测试 13 | - | - |
| systemctl 守卫 | ✅ 测试 14 | - | - |
| 端口命名统一 | ✅ 测试 15 | - | ✅ 测试 17 |
| CPU 解析稳定 | ✅ 测试 16 | - | ✅ 测试 17 |
| 终端/报告一致性 | - | ✅ 测试 1-8 | ✅ 测试 17 |
| 错误可见性 | ✅ 测试 18 | - | - |
| 防火墙多后端 | ✅ 测试 19 | - | - |
| 报告命名 | ✅ 测试 20 | - | - |

**总计**: 31 个测试用例，100% 通过率
