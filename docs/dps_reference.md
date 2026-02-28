# DPS Channels — Wilfa Haze HU-400BCA

Tuya devices use numbered DPS (Data Point Service) channels. Each one maps to a device function. Data goes back and forth as JSON over TCP 6668, encrypted with AES-128-ECB (protocol 3.3).

## Channel map

| DPS | Type | What it is | Values |
|-----|------|-----------|--------|
| 1 | `bool` | Power | `true`/`false` |
| 5 | `bool` | Child lock | `true` = locked |
| 8 | `bool` | Sound | `true` = on |
| 10 | `int` | Current temp (°C) | Read-only |
| 13 | `int` | Target humidity (%) | Writable |
| 14 | `int` | Current humidity (%) | Read-only |
| 16 | `bool` | Warm mist | `true` = on |
| 19 | `string` | Timer mode | `"cancel"`, etc. |
| 20 | `int` | Timer remaining | Minutes |
| 22 | `int` | Unknown | Seen in status, purpose unclear |
| 23 | `string` | Fan speed | `"level_1"` through `"level_5"` |
| 24 | `string` | Mode | `"auto"`, `"manual"` |
| 26 | `bool` | Sleep mode | `true` = on |
| 35 | `bool` | Display light | `true` = on |

## Reading status

```python
import tinytuya

d = tinytuya.Device('DEVICE_ID', 'DEVICE_IP', 'LOCAL_KEY', version=3.3)
print(d.status()['dps'])
# {'1': False, '5': False, '8': True, '10': 23, '13': 30, '14': 23, ...}
```

## Setting values

```python
d.set_value(1, True)           # turn on
d.set_value(23, "level_3")     # fan speed
d.set_value(13, 50)            # target humidity
d.set_value(24, "manual")      # mode
```

## Notes

- DPS 10 and 14 are read-only (sensor data)
- DPS 22 shows up in status responses but I haven't figured out what it does
- Fan speed definitely goes up to level_3, possibly level_5
