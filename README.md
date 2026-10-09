# CodeAlpha_NetworkIDS

**CodeAlpha Cyber Security Internship — Task 4: Network Intrusion Detection System**

Mise en place d'un IDS réseau avec Snort 3 (Snort++) sur Kali Linux. Deux règles locales ont été ajoutées (détection ICMP et scan SYN), la configuration a été validée (`snort -T`, 0 warning), puis testée en conditions réelles sur `wlan0` contre la passerelle du réseau local. Les alertes obtenues sont fournies dans `logs/alert_fast_sample.log`.

## Stack

- Snort 3 / Snort++ 3.12.2.0 (`apt install snort`)
- Kali Linux, interface `wlan0`
- Réseau `192.168.1.0/24` (`HOME_NET`), hôte `192.168.1.69`, passerelle `192.168.1.254`

## Structure du dépôt

- [`NIDS_REPORT.md`](./NIDS_REPORT.md) — rapport : méthodologie, détail des règles, preuve de concept, limites
- [`snort-config/snort.lua.snippet`](./snort-config/snort.lua.snippet) — extraits modifiés de `/etc/snort/snort.lua` (`HOME_NET` et bloc `ips`)
- [`snort-config/local.rules`](./snort-config/local.rules) — règles personnalisées
- [`logs/alert_fast_sample.log`](./logs/alert_fast_sample.log) — alertes `alert_fast` capturées pendant les tests

## Reproduire

1. Installer Snort 3 :

```bash
sudo apt install snort
```

2. Copier les règles locales vers `/etc/snort/rules/local.rules`, puis dans `/etc/snort/snort.lua` régler `HOME_NET` sur `'192.168.1.0/24'` et inclure les règles dans le bloc `ips` (voir `snort-config/snort.lua.snippet`).

3. Valider la configuration :

```bash
sudo snort -c /etc/snort/snort.lua -T
```

4. Lancer la surveillance :

```bash
sudo snort -c /etc/snort/snort.lua -i wlan0 -A alert_fast -q
```

Le détail de la configuration, des règles et des logs de test est dans le [rapport](./NIDS_REPORT.md).
