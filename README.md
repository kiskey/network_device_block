# LAN Access Scheduler (LIAS)

A single, statically linked Go binary that provides an Apple-inspired web dashboard to control Internet access of LAN devices using MAC-based schedules.

It operates entirely on a dedicated **netdev nftables table**, ensuring VPN routing, NAT, and existing firewall logic are never touched.

---

# 📖 Control & Precedence Guide

## 1. The Evaluation Hierarchy (Precedence Flow)

When a packet arrives at the gateway, the system evaluates rules in a strict, top-down hierarchy.

The first rule that matches the device's state is applied immediately.

```
┌─────────────────────────────────────────────────────────┐
│                   PACKET ARRIVES AT eth0                │
└─────────────────────────────┬───────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────┐
│ 1. INSTANT PAUSE (Device Toggle Switch)                 │
│                                                         │
│ Is the device manually "Paused" via the UI toggle?      │
│                                                         │
│ • YES → DROP Packet (Internet Cut Off Immediately)      │
│ • NO  → Continue to next rule                          │
└─────────────────────────────┬───────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────┐
│ 2. GLOBAL POLICY (If "Global Override" is ENABLED)      │
│                                                         │
│ Is the Global Master Toggle turned ON?                 │
│                                                         │
│ • YES → Apply Global Mode (Allow / Block / Schedule)   │
│         (Ignores all individual device rules)           │
│                                                         │
│ • NO  → Continue to next rule                           │
└─────────────────────────────┬───────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────┐
│ 3. DEVICE OVERRIDE POLICY                               │
│                                                         │
│ Does the device have a custom mode set?                 │
│                                                         │
│ (Allow / Block / Scheduled Downtime / Whitelist)        │
│                                                         │
│ • YES → Apply Device Mode                               │
│ • NO  → Continue to next rule                           │
└─────────────────────────────┬───────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────┐
│ 4. DEFAULT FALLBACK                                     │
│                                                         │
│ Allow internet access (Fail-open)                       │
└─────────────────────────────────────────────────────────┘
```

## Traffic Scope

Local LAN traffic is NEVER dropped.

Examples:

- Printing to local printers.
- Accessing NAS devices.
- DNS requests to the gateway.
- Internal LAN communication.
- Device discovery.

Only Internet-bound (WAN) traffic is blocked.

---

# 2. Global Level Controls

Accessed through the **Schedule** tab.

These settings act as the master control for the entire network.

| Control | Description |
|---|---|
| Enable Global Override | A master switch. If ON, all device-specific rules are ignored, and every device follows the Global Mode. If OFF, devices use their own custom rules. |
| Default Mode | Defines the baseline behavior for all devices when Global Override is active. |
| Save Schedule | Automatically forces Global Mode to Scheduled Downtime and applies configured time blocks. |

---

# Global Modes Available

## 🟢 Allow Always

The Internet is open for all devices.

Behavior:

- No restrictions.
- All devices can access the Internet.

---

## 🔴 Block Always

The Internet is completely cut off for all devices.

Behavior:

- All WAN access is denied.
- LAN communication continues normally.

---

## 📅 Scheduled Downtime

Internet is allowed except during configured scheduled times.

Example:

```
Bedtime Schedule:

22:00 - 07:00
```

Result:

- Internet available during daytime.
- Internet blocked during bedtime.

---

## ⏱️ Scheduled Whitelist

Internet is blocked except during configured scheduled times.

Example:

```
Homework Schedule:

16:00 - 18:00
```

Result:

- Internet disabled by default.
- Internet enabled only during allowed windows.

---

# 3. Device Level Controls

Accessed by clicking the `>` arrow next to any device in the Devices tab.

These controls provide granular exceptions to global rules.

---

# Device Controls

| Control | Description |
|---|---|
| Instant Toggle (Pause) | The switch on the main device list. Clicking instantly cuts Internet access without destroying the underlying schedule. Unpausing restores the scheduled policy. |
| Friendly Name | Custom label used to identify devices. Example: "John's iPhone". |
| Policy Mode | Defines the specific rule for this MAC address. |

---

# Device Modes Available

## 🌐 Use Global Policy

Default behavior.

The device inherits whatever Global Policy is configured.

---

## 🟢 Allow Always

This device is always allowed.

Acts as a whitelist exception.

Example:

```
Global Mode:
Block Always

Device Mode:
Allow Always

Result:
Device still has Internet access.
```

---

## 🔴 Block Always

This device is always blocked.

Behavior:

- Ignores normal schedules.
- Internet access is permanently denied.

---

## 📅 Scheduled Downtime

Device is allowed except during its own custom schedule.

Example:

```
22:00 - 07:00
```

Result:

- Internet works normally.
- Internet blocked during configured downtime.

---

## ⏱️ Scheduled Whitelist

Device is blocked except during its own custom schedule.

Behavior:

- Default state is denied.
- Internet allowed only during configured windows.

---

# 4. Scenario Matrix

| Scenario | Global Override | Global Mode | Device Mode | Result for Device |
|---|---|---|---|---|
| Open Network | OFF | Allow Always | Use Global | 🟢 Internet Allowed |
| Network Lockdown | ON | Block Always | Allow Always | 🔴 Internet Blocked (Global wins) |
| Whitelist Exception | OFF | Block Always | Allow Always | 🟢 Internet Allowed (Device wins) |
| Dinner Time Pause | OFF | Allow Always | Toggle Paused | 🔴 Internet Blocked (Instant) |
| Global Bedtime | ON | Scheduled Downtime | Allow Always | 🔴 Blocked during Global Schedule |
| Device Bedtime | OFF | Allow Always | Scheduled Downtime | 🔴 Blocked during Device Schedule |
| Homework Time | OFF | Allow Always | Scheduled Whitelist | 🔴 Blocked, except during Schedule |

---

# ⏱️ Deep Dive: How "Scheduled Whitelist" Works

The Scheduled Whitelist (`SCHEDULE_ALLOW`) is the inverse of standard downtime.

It operates using a **Default Deny** security model for that specific device.

By default:

```
Internet Access = BLOCKED
```

Access is only granted during explicitly configured time windows.

---

# Use Case Example: Gaming Console

A child has a gaming console.

Allowed usage:

```
Saturday:
14:00 - 17:00

Sunday:
14:00 - 17:00
```

Outside these times:

```
Internet Access:
Denied
```

---

# Configuration Steps

1. Open the Devices tab.

2. Click the `>` arrow next to the gaming console.

3. Select:

```
Policy Mode:
Scheduled Whitelist (Allow during)
```

4. Add schedule rules:

```
Sunday:
14:00 - 17:00

Saturday:
14:00 - 17:00
```

5. Click:

```
Save Changes
```

---

# Timeline of Behavior

## Saturday 1:00 PM

The console attempts to connect to:

- PlayStation Network.
- Xbox Live.
- Online gaming services.

Scheduler evaluates:

```
SCHEDULE_ALLOW
```

Current time:

```
13:00
```

Allowed window:

```
14:00 - 17:00
```

Result:

```
🔴 MAC address added to blocked_macs nftables set.

Internet access denied.
```

---

## Saturday 2:00 PM

Background scheduler executes its 60-second cycle.

Current time:

```
14:00
```

The device is inside the allowed window.

Result:

```
🟢 MAC address removed from blocked_macs.

MAC address added to override_allow.

Internet access granted.
```

---

## Saturday 5:01 PM

Background scheduler executes.

Current time:

```
17:01
```

The allowed window has expired.

Result:

```
🔴 MAC address moved back to blocked_macs.

Existing connections dropped.

New Internet traffic denied.
```

---

# Why Scheduled Whitelist Is Powerful

Unlike Scheduled Downtime, where you define when blocking occurs, Scheduled Whitelist creates a strict access boundary.

Benefits:

- Device reboot does not bypass restrictions.
- IP address changes do not matter.
- DNS bypass attempts do not matter.
- VPN attempts do not matter.
- MAC-based enforcement happens at the network interface layer.

The device receives Internet access only when the scheduler explicitly allows it.
