# Качество и задержка видеострима на Raspberry Pi

В проекте сейчас есть три основных H.264 режима:

- `udp_h264` — рекомендуемый operator pipeline: `H.264` внутри `MPEG-TS/UDP`;
- `h264_tcp` — совместимый H.264/TCP режим;
- `rtsp_h264` — RTSP/H.264 server на Pi.

`rtp_h264` в текущем CLI временно работает как alias на `udp_h264`, потому что прямой RTP/H.264 путь в этом стеке оказался нестабилен для Windows/GStreamer.

Старый `jpeg_tcp` оставлен только для совместимости и overlay-сценариев.

## Что использовать

Если видео нужно именно для управления роботом, основной режим теперь такой:

```bash
python stream_camera.py send --video-mode udp_h264 --host 10.42.0.2 --port 5000 --stream-preset realtime
```

Если Pi поднимает hotspot:

```bash
python stream_camera.py send --ap-ssid 12345 --ap-force --video-mode udp_h264 --host 10.42.0.194 --port 5000 --stream-preset realtime
```

Где `10.42.0.194` — IP ПК внутри hotspot Pi.

Если нужна совместимость с более простым подключением:

```bash
python stream_camera.py send --listen --video-mode h264_tcp --stream-preset cinema
```

Если нужен RTSP endpoint:

```bash
python stream_camera.py send --video-mode rtsp_h264 --port 8554 --rtsp-path camera --stream-preset realtime
```

## Почему сейчас основной режим именно UDP/MPEG-TS

Для operator video схема `udp_h264 + GStreamer` уже подтверждена как рабочая на Pi и Windows:

- не требует SDP/RTSP negotiation;
- не зависит от проблемного direct RTP/H.264 packetization;
- хорошо сочетается с `rpicam-vid` через `libav`;
- дает низкую задержку и устойчивый декод на ПК.

## Почему TCP может давать секунды задержки

Даже при `--flush`, коротком `--video-intra` и low-latency настройках player'а схема `H.264 over TCP` все равно может запаздывать:

- TCP буферизует поток;
- при потерях появляются retransmit и head-of-line blocking;
- player позже добирается до "живого" кадра.

Поэтому для оператора TCP не является основным режимом.

## Что включено в H.264 пути на Pi

И для `h264_tcp`, и для `udp_h264` / `rtsp_h264` на Pi используются:

- `--flush`, чтобы кадры уходили сразу;
- `--inline`, чтобы SPS/PPS повторялись на IDR;
- аппаратный H.264 encoder через `rpicam-vid` / `libcamera-vid`;
- более короткий `--video-intra` по умолчанию: `15`.

## Основные параметры

- `--video-mode udp_h264` — основной операторский `MPEG-TS/UDP` режим на `--host:<port>`.
- `--video-mode h264_tcp` — H.264/TCP, Pi слушает входящее подключение.
- `--video-mode rtsp_h264` — RTSP service на Pi.
- `--video-bitrate BPS` — целевой битрейт. Слишком высокий битрейт на слабом Wi-Fi увеличивает лаг и потери.
- `--video-intra N` — интервал IDR/I-frame. Меньше значение ускоряет recovery.
- `--video-profile high|main|baseline` — профиль H.264.
- `--width`, `--height`, `--fps` — напрямую влияют и на качество, и на задержку.

## Пресеты

- `broadcast` — `1080p30`, высокий битрейт, основной качественный режим.
- `cinema` — `1080p24`, максимум качества.
- `mobile` — `720p30`, ниже битрейт, для более узкого канала.
- `realtime` — `960x540`, `4 Мбит/с`, `video_intra=10`, самый агрессивный low-latency режим.
- `custom` — только явно заданные параметры.

Для `udp_h264` и `rtp_h264` пресет `broadcast` автоматически заменяется на `realtime`, если пользователь не выбрал свой.

## Практические команды

### Основной operator режим

```bash
python stream_camera.py send --video-mode udp_h264 --host 10.42.0.2 --port 5000 --stream-preset realtime
```

### Hotspot Pi -> ПК

```bash
python stream_camera.py send --ap-ssid 12345 --ap-force --video-mode udp_h264 --host 10.42.0.194 --port 5000 --stream-preset realtime
```

### UDP с ручными параметрами

```bash
python stream_camera.py send --video-mode udp_h264 --host 10.42.0.2 --port 5000 --stream-preset custom --width 1280 --height 720 --fps 30 --video-bitrate 8000000 --video-intra 10 --video-profile main
```

### Максимум качества по TCP

```bash
python stream_camera.py send --listen --video-mode h264_tcp --stream-preset cinema --video-bitrate 50000000
```

## Что чаще всего увеличивает задержку

- `1080p` там, где каналу реально подходит `720p` или `960x540`;
- слишком высокий `--video-bitrate` для конкретного Wi-Fi;
- длинный GOP / редкие I-frame;
- транспорт `TCP`, если нужна почти живая картинка;
- overlay через `--timestamp`, потому что он уводит в legacy JPEG путь.

## Прием на ПК

### Для `udp_h264`

Linux/macOS:

```bash
gst-launch-1.0 -q udpsrc port=5000 buffer-size=262144 ! tsdemux ! h264parse ! decodebin ! videoconvert ! autovideosink sync=false
```

Windows:

```powershell
& "C:\Users\pavel\AppData\Local\Programs\gstreamer\1.0\msvc_x86_64\bin\gst-launch-1.0.exe" -q udpsrc port=5000 buffer-size=262144 ! tsdemux ! h264parse ! avdec_h264 ! videoconvert ! d3d11videosink sync=false
```

Или helper:

```bash
python3 examples/pc_parallel_client.py --host IP_PI
```

### Для `h264_tcp`

```bash
gst-launch-1.0 tcpclientsrc host=IP_PI port=5000 ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false
```

## Legacy JPEG режим

Если нужен старый поток `4-byte length + JPEG`, запускайте:

```bash
python stream_camera.py send --listen --video-mode jpeg_tcp
```

Этот режим полезен только для совместимости и overlay-сценариев.
