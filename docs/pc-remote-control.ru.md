# Управление роботом с ПК по Wi-Fi

Текущая рабочая схема для оператора:

1. Видео с Pi — `udp_h264` (`H.264` внутри `MPEG-TS/UDP`).
2. Приемник на ПК — `GStreamer`.
3. Команды Romeo — отдельный `TCP`-порт с UTF-8 строками и NDJSON-ответами.

`rtp_h264` пока оставлен в CLI только как временный alias на стабильный `udp_h264`, потому что прямой RTP/H.264 в текущем стеке оказался нестабилен на Windows/GStreamer.

## 1. Основной операторский запуск

### На Raspberry Pi

Если ПК уже в домашней сети:

```bash
python stream_camera.py send --video-mode udp_h264 --host 192.168.1.8 --port 5000 --stream-preset realtime
```

Если Pi должна сама поднять hotspot:

```bash
python stream_camera.py send --ap-ssid 12345 --ap-force --video-mode udp_h264 --host 10.42.0.194 --port 5000 --stream-preset realtime
```

Где:

- `192.168.1.8` или `10.42.0.194` — IP ПК;
- `5000` — UDP порт видео;
- `5001` по умолчанию остается под control.

### На ПК через GStreamer

Linux/macOS:

```bash
gst-launch-1.0 -q udpsrc port=5000 buffer-size=262144 ! tsdemux ! h264parse ! decodebin ! videoconvert ! autovideosink sync=false
```

Windows:

```powershell
& "C:\Users\pavel\AppData\Local\Programs\gstreamer\1.0\msvc_x86_64\bin\gst-launch-1.0.exe" -q udpsrc port=5000 buffer-size=262144 ! tsdemux ! h264parse ! avdec_h264 ! videoconvert ! d3d11videosink sync=false
```

### Через helper из репозитория

Домашняя сеть:

```bash
python3 examples/pc_parallel_client.py --host 192.168.1.50
```

Hotspot Pi:

```bash
python3 examples/pc_parallel_client.py --host 10.42.0.1
```

Здесь `--host` — это IP самой Pi для control, а видео helper принимает локально на `UDP 5000`.

## 2. Что важно для hotspot

Если ПК подключен к точке доступа Pi, то:

- Pi обычно имеет адрес `10.42.0.1`;
- ПК получает адрес вида `10.42.0.x`;
- именно этот адрес ПК нужно указывать в `--host` на Pi для видеопотока.

Пример:

- Pi: `10.42.0.1`
- ПК: `10.42.0.194`

Тогда:

- на Pi видео идет на `10.42.0.194:5000`
- на ПК control идет к `10.42.0.1:5001`

## 3. Отдельное TCP-соединение под команды

Откройте один долгоживущий TCP-клиент на `IP_PI:control`, например `10.42.0.1:5001`.

- кодировка: `UTF-8`;
- одна команда = одна строка + `
`;
- ответ Pi: одна JSON-строка на каждую входную строку.

Пример ответа:

```json
{"ok": true, "reply": "OK\r\n"}
```

При ошибке:

```json
{"ok": false, "error": "..."}
```

## 4. Что слать на Pi

Можно слать либо текстовые команды прошивки Romeo, либо JSON-строки.

### Текстом

```text
MF
MB
MS
TANK 200 -200
PL
PR
TS
HOME
```

### JSON

- Вперед / назад / стоп: `{"action":"drive","dir":"forward"}`, `"back"`, `"stop"`
- Две гусеницы: `{"action":"tank","left":200,"right":-200}`
- Башня шагом: `{"action":"turret","dir":"left","step":1}`
- Плавная башня: `{"action":"turret_smooth","dir":"left","v":20}`
- Скорости PAN/TILT: `{"action":"pan_vel","v":12}`, `{"action":"tilt_vel","v":-8}`
- Обе оси: `{"action":"turret_vel","pan":10,"tilt":3}`
- Стоп башни: `{"action":"turret_stop"}`
- Домой: `{"action":"home"}`
- АЦП: `{"action":"adc_read"}` или `{"action":"adc_read","ch":3}`

## 5. Батарея и АЦП

Команда `{"action":"adc_read"}` возвращает строку вида `A1 512 2502` в `reply` и дополнительные поля:

- `adc_raw`
- `adc_pin_mv`
- `adc_pin_mv_cal`
- `battery_v`

Для UI на ПК используйте `battery_v`, а не сырой ADC код.

## 6. Практика для клавиатуры

- Для моторов: на `keydown` шлите одну команду движения, на `keyup` шлите `stop`.
- Для башни: лучше `turret_smooth` на `keydown` и `turret_stop` на `keyup`.
- Не используйте keyboard autorepeat как единственный источник команд.
- Управление всегда держите в отдельном TCP-соединении от видео.

## 7. Альтернативные режимы

Если нужен совместимый или диагностический путь:

- `--video-mode h264_tcp` — проще, но выше задержка;
- `--video-mode rtsp_h264` — RTSP server на Pi, если нужно именно `rtsp://`;
- `--video-mode jpeg_tcp` — старый `4-byte length + JPEG`.
