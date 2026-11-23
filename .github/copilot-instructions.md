# Copilot Instructions

## General Guidelines
- Wenn der Nutzer sich bei Frequenzangaben vertippt, zuerst kurz verifizieren statt Annahmen treffen; hier war 5 GHz gemeint, nicht 2,4 GHz.
- Wenn ein Vorgang oder Tool-Aufruf unterbrochen wird, sofort stoppen, den Fehler analysieren und beheben, bevor weitere Schritte oder neue Änderungen gestartet werden.

## Projektrichtlinien
- Im ArubaOS-Setup des Nutzers (AP-325, AOS 8.3) wird Konfiguration mit 'commit apply' statt 'write memory' gespeichert/angewendet.
- Bei WLAN-Analyse nur auf bestätigte Gegebenheiten aufbauen (5GHz-only, keine Verkabelungsänderung); keine pauschalen Kabel/Port-Vermutungen.
- Bei WLAN-Dashboards nur die im Aruba-Screenshot gezeigten Metriken umsetzen: Name, IP-Adresse, Modus, Spektrum, Clients, Typ, Mesh-Rolle, Zone, Seriennummer sowie je Funkband Kanal, Leistung, Auslastung und Rauschen. Korrigiere gezielt den Clients-Wert, ohne weitere Spalten oder Logik zu ändern, wenn nicht ausdrücklich gewünscht. Keine redundanten Zusatzpanels oder erfundenen Metriken hinzufügen.
- Im 2,4-GHz-Panel sollen nur Kanäle 1-11 verwendet werden; Kanal 13 ist im Nutzer-Setup nicht im Einsatz.