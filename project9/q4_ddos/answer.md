# Ερώτημα 4: Single Point of Failure & Αντιμετώπιση DDoS

## Περιγραφή

Ένας MQTT broker εγκατεστημένος σε έναν μόνο server αποτελεί Single Point of Failure (SPOF)
— αν ο server αποτύχει, ολόκληρο το IoT σύστημα παύει να λειτουργεί. Επιπλέον, είναι ευάλωτος
σε επιθέσεις DDoS που στοχεύουν στην εξάντληση των πόρων του.

## i. Αύξηση Διαθεσιμότητας

**Clustering / Broker Redundancy**
Χρήση πολλαπλών MQTT brokers σε cluster, όπως το EMQX ή το HiveMQ, που υποστηρίζουν
κατανεμημένη αρχιτεκτονική. Αν ένας broker αποτύχει, οι clients συνδέονται αυτόματα σε άλλον.

**Load Balancer**
Τοποθέτηση Load Balancer (π.χ. HAProxy, NGINX) μπροστά από τους brokers για κατανομή του
traffic. Παρέχει και health checking — αν ένας broker πέσει, ο Load Balancer σταματά να του
στέλνει connections.

**Message Persistence**
Ενεργοποίηση persistence στον Mosquitto (`persistence true`) ώστε τα μηνύματα να
αποθηκεύονται στο δίσκο. Σε περίπτωση επανεκκίνησης δεν χάνονται δεδομένα.

**Αυτόματη Επανεκκίνηση**
Ρύθμιση του broker ως system service με αυτόματη επανεκκίνηση σε περίπτωση αποτυχίας
(`RestartAlways` σε Linux systemd ή `Install Service` σε Windows).

## ii. Περιορισμός DDoS Επιθέσεων

**Rate Limiting Connections**
Περιορισμός αριθμού συνδέσεων ανά IP στον Mosquitto:
```
max_connections 100
```

**Firewall Rules**
Χρήση firewall (π.χ. iptables, Windows Defender Firewall) για περιορισμό πρόσβασης στα ports
1883/8883 μόνο από γνωστές IP διευθύνσεις.

**Authentication & ACL**
Όπως υλοποιήθηκε στα Ερωτήματα 1 και 2 — η αυθεντικοποίηση αποτρέπει μαζικές ανώνυμες
συνδέσεις που αποτελούν βασικό φορέα DDoS.

**TLS**
Όπως υλοποιήθηκε στο Ερώτημα 3 — το TLS αυξάνει το υπολογιστικό κόστος για τον
επιτιθέμενο, μειώνοντας την αποτελεσματικότητα της επίθεσης.

**CDN / Anti-DDoS Service**
Χρήση υπηρεσιών όπως Cloudflare ή AWS Shield για απορρόφηση μεγάλου όγκου traffic πριν
φτάσει στον broker.

**Message Size Limiting**
Περιορισμός μεγέθους μηνυμάτων στον Mosquitto:
```
message_size_limit 1024
```

## Συμπέρασμα

Η αντιμετώπιση του SPOF και των DDoS επιθέσεων απαιτεί συνδυασμό αρχιτεκτονικών λύσεων
(clustering, load balancing) και τεχνικών μέτρων ασφάλειας (rate limiting, firewall, authentication).
Τα μέτρα των Ερωτημάτων 1-3 αποτελούν τη βάση της θωράκισης, ενώ η κατανεμημένη
αρχιτεκτονική εξασφαλίζει συνέχεια λειτουργίας σε περίπτωση αποτυχίας.