# Rapport — Network Intrusion Detection System

**CodeAlpha Cyber Security Internship — Task 4 : Network Intrusion Detection System**

| Champ | Détail |
|---|---|
| **Student ID** | CA/DF1/306228 |
| **Domaine** | Cyber Security |
| **Batch** | 1–30 octobre 2026 |
| **IDS** | Snort 3 (Snort++) 3.12.2.0 |
| **Date des tests** | 9 octobre 2026 |

---

## 1. Résumé exécutif

L'objectif de cette tâche était de déployer un système de détection d'intrusion réseau (NIDS) sur une machine Kali Linux, de le rattacher au réseau local, d'écrire des règles de détection personnalisées, puis de les valider par une preuve de concept.

**Environnement :** interface `wlan0`, adresse `192.168.1.69`, réseau `192.168.1.0/24` (`HOME_NET`), passerelle `192.168.1.254`.

**Résultat :** deux règles locales (SID 1000001 : ping ICMP ; SID 1000002 : scan SYN) ont été chargées avec les règles intégrées de Snort. La configuration a été validée sans warning (`total rules loaded: 868`). Les deux règles ont ensuite été confirmées en conditions réelles : ping puis scan SYN (`nmap -sS`) vers la passerelle, avec alertes `alert_fast` correspondantes.

---

## 2. Méthodologie

1. **Identification de l'interface et du réseau** — `wlan0`, `192.168.1.0/24`, hôte `192.168.1.69`, passerelle `192.168.1.254`.
2. **Installation** — Snort 3 via `apt install snort` (version 3.12.2.0).
3. **Configuration de `HOME_NET`** — dans `/etc/snort/snort.lua`, `HOME_NET` réglé sur `'192.168.1.0/24'` pour limiter la détection au réseau local.
4. **Écriture des règles** — fichier `/etc/snort/rules/local.rules`, inclus dans le bloc `ips` de `snort.lua`.
5. **Validation syntaxique** — `sudo snort -c /etc/snort/snort.lua -T` :

```
Snort successfully validated the configuration (with 0 warnings).
total rules loaded: 868
text rules: 221
builtin rules: 647
```

6. **Test en conditions réelles** — Snort lancé en surveillance sur `wlan0`, puis génération de trafic ICMP et d'un scan SYN vers la passerelle.

Commande de surveillance :

```bash
sudo snort -c /etc/snort/snort.lua -i wlan0 -A alert_fast -q
```

---

## 3. Détail des règles

Fichier : `/etc/snort/rules/local.rules`

### 3.1 ICMP Ping (SID 1000001)

```
alert icmp any any -> $HOME_NET any ( msg:"ICMP Ping detecte"; sid:1000001; rev:1; )
```

| Champ | Valeur | Rôle |
|---|---|---|
| Action | `alert` | Génère une alerte, sans bloquer le trafic |
| Protocole | `icmp` | Paquets ICMP uniquement |
| Source | `any any` | N'importe quelle adresse / pas de port ICMP |
| Direction | `->` | Vers `$HOME_NET` |
| Destination | `$HOME_NET any` | Toute machine du réseau `192.168.1.0/24` |
| `msg` | `ICMP Ping detecte` | Libellé affiché dans les logs |
| `sid` | `1000001` | Identifiant local (plage utilisateur ≥ 1 000 000) |
| `rev` | `1` | Première révision |

Cette règle signale tout ping ICMP à destination du réseau local. Elle sert de contrôle de base : le moteur charge bien les règles locales et produit une alerte sur un trafic simple et reproductible.

### 3.2 Scan de ports SYN (SID 1000002)

```
alert tcp any any -> $HOME_NET any ( msg:"Scan de ports possible SYN"; flags:S; detection_filter:track by_src, count 5, seconds 10; sid:1000002; rev:1; )
```

| Champ | Valeur | Rôle |
|---|---|---|
| Action | `alert` | Alerte uniquement |
| Protocole | `tcp` | Segments TCP |
| Source / destination | `any any -> $HOME_NET any` | SYN vers n'importe quel port du réseau local |
| `msg` | `Scan de ports possible SYN` | Libellé |
| `flags` | `S` | Bit SYN seul (handshake initial, typique d'un scan `-sS`) |
| `detection_filter` | `track by_src, count 5, seconds 10` | Seuil : 5 événements depuis la même source en 10 secondes |
| `sid` | `1000002` | Identifiant local |
| `rev` | `1` | Première révision |

Le seuil **5 paquets SYN / 10 secondes**, suivi **par source**, vise à séparer un scan (rafale de SYN vers plusieurs ports) d'une ouverture de connexion isolée. Un client légitime qui établit une session TCP unique ne franchit pas ce seuil ; un `nmap -sS` le franchit immédiatement.

---

## 4. Preuve de concept

Snort était en écoute sur `wlan0`. Les tests ont ciblé la passerelle `192.168.1.254` :

```bash
ping -c 4 192.168.1.254
sudo nmap -sS 192.168.1.254
```

Alertes `alert_fast` obtenues :

```
10/09-10:24:02.657266 [**] [1:1000001:1] "ICMP Ping detecte" [**] [Priority: 0] {ICMP} 192.168.1.254 -> 192.168.1.69
10/09-10:24:03.656939 [**] [1:1000001:1] "ICMP Ping detecte" [**] [Priority: 0] {ICMP} 192.168.1.69 -> 192.168.1.254
10/09-10:24:03.658369 [**] [1:1000001:1] "ICMP Ping detecte" [**] [Priority: 0] {ICMP} 192.168.1.254 -> 192.168.1.69
10/09-10:24:04.658638 [**] [1:1000001:1] "ICMP Ping detecte" [**] [Priority: 0] {ICMP} 192.168.1.69 -> 192.168.1.254
10/09-10:24:04.660123 [**] [1:1000001:1] "ICMP Ping detecte" [**] [Priority: 0] {ICMP} 192.168.1.254 -> 192.168.1.69
10/09-10:24:05.660468 [**] [1:1000001:1] "ICMP Ping detecte" [**] [Priority: 0] {ICMP} 192.168.1.69 -> 192.168.1.254
10/09-10:24:05.665518 [**] [1:1000001:1] "ICMP Ping detecte" [**] [Priority: 0] {ICMP} 192.168.1.254 -> 192.168.1.69
10/09-10:24:59.949526 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60251 -> 192.168.1.254:3306
10/09-10:24:59.949544 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60251 -> 192.168.1.254:1723
10/09-10:24:59.949562 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60251 -> 192.168.1.254:25
10/09-10:24:59.949582 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60251 -> 192.168.1.254:1025
10/09-10:24:59.949602 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60251 -> 192.168.1.254:554
10/09-10:25:01.049981 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60253 -> 192.168.1.254:554
10/09-10:25:01.050155 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60253 -> 192.168.1.254:1025
10/09-10:25:01.050246 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60253 -> 192.168.1.254:25
10/09-10:25:01.050380 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60253 -> 192.168.1.254:1723
10/09-10:25:01.050552 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60253 -> 192.168.1.254:3306
10/09-10:25:01.050679 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60253 -> 192.168.1.254:23
10/09-10:25:01.050822 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60253 -> 192.168.1.254:21
10/09-10:25:01.050999 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60253 -> 192.168.1.254:995
10/09-10:25:01.051089 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60253 -> 192.168.1.254:143
10/09-10:25:01.051177 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60253 -> 192.168.1.254:1720
10/09-10:25:01.150470 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60251 -> 192.168.1.254:139
10/09-10:25:01.152942 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60251 -> 192.168.1.254:199
10/09-10:25:01.152998 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60251 -> 192.168.1.254:256
10/09-10:25:01.153025 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60251 -> 192.168.1.254:443
10/09-10:25:01.153052 [**] [1:1000002:1] "Scan de ports possible SYN" [**] [Priority: 0] {TCP} 192.168.1.69:60251 -> 192.168.1.254:993
```

Les SID correspondent aux règles locales (`1:1000001:1` et `1:1000002:1`). Le ping produit une alerte par paquet ICMP observé (requête et réponse, d'où les deux sens `192.168.1.69` ↔ `192.168.1.254`). Le scan `nmap -sS` produit une alerte par port testé (3306, 1723, 25, 1025, 554, 23, 21, etc.), une fois le `detection_filter` franchi.

---

## 5. Limites connues

- La règle SYN repose sur un seuil fixe (5 / 10 s). Un trafic légitime très actif depuis une même source (nombreuses ouvertures TCP courtes) peut déclencher des faux positifs.
- Aucun mécanisme de réponse automatique (blocage, bannissement, IPS) n'a été mis en place : hors périmètre de cette tâche. Snort a été utilisé en détection (`alert`), pas en prévention.

---

## 6. Conclusion

Snort 3 a été installé, rattaché au réseau `192.168.1.0/24`, et étendu par deux règles locales. La configuration se charge sans warning (868 règles au total). Les tests ICMP et SYN vers `192.168.1.254` ont produit les alertes attendues, ce qui confirme que le NIDS voit le trafic de `wlan0` et applique bien les règles personnalisées.
