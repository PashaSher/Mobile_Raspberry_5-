Тестовая запись микрофона Voice HAT (16 kHz, mono).

Файл: mic_test_latest.wav

Скачать на телефон/ПК (Tailscale или LAN):
  scp pavel@100.73.9.95:/home/pavel/projects/Mobile_Raspberry_5-/recordings/mic_test_latest.wav .

Или с Pi на флешку:
  cp recordings/mic_test_latest.wav /media/...

Перезапись на Pi:
  arecord -D plughw:2,0 -f S16_LE -r 16000 -c 1 -d 10 recordings/mic_test_latest.wav
