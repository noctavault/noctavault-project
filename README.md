# Noctavault

*[English version](README.en.md)*

Cloud de fichiers chiffrés, **résistant post-quantique**, sur un réseau
**public mondial** : pas d'autorité centrale, n'importe qui peut faire
tourner un nœud et rejoindre le réseau. L'anti-spam est assuré par une
limite de débit par identité, pas par une inscription ou une permission.

Ajouter un fichier produit un manifeste texte léger (`.nvault`, quelques
Ko) : le contenu réel est chiffré et éclaté en chunks diffusés sur le
réseau, irrécupérable sans la clé privée du propriétaire — ou celle d'un
destinataire explicitement choisi au moment du partage.

## Pourquoi post-quantique

Toute l'identité et le chiffrement reposent sur des primitives
post-quantiques normalisées (NIST), via les implémentations PQClean :

- **ML-KEM-1024** pour l'encapsulation de clé (confidentialité).
- **ML-DSA-65** pour la signature (authenticité).

Un fichier est chiffré avec une clé AES-256 aléatoire, elle-même
encapsulée séparément pour chaque destinataire via sa clé publique
ML-KEM — c'est ce qui permet le partage multi-destinataires sans jamais
faire circuler la clé en clair.

## Comment ça circule

Chaque transaction (chunk chiffré, manifeste publié, révocation) est
signée par son émetteur et s'authentifie elle-même — pas besoin de bloc
ni de minage. Diffusion par **gossip** : une transaction reçue, valide et
nouvelle est relayée à tous les pairs connus ; un doublon est ignoré, ce
qui arrête l'inondation toute seule. L'anti-spam est une **limite de
débit par identité** (transactions par minute), pas une preuve de
travail. La découverte de pairs se fait par mDNS sur le réseau local et
par échange de pairs (PEX) pour Internet.

Pour qu'un tout nouvel arrivant puisse rejoindre le réseau sans connaître
personne (mDNS ne marche que sur le même réseau local), `nv-node` se
connecte par défaut à un **nœud d'amorçage** public si aucun pair n'est
configuré. Une fois connecté à ne serait-ce qu'un seul pair, la
découverte (PEX) et la synchronisation prennent le relais tout seuls.

## Architecture

```
crates/
  nv-core/   identité post-quantique, format de fichier .nvault et .nvid
  nv-chain/  ledger de transactions signées, rate-limit, révocation
  nv-net/    réseau : gossip, synchronisation, mDNS/PEX
  nv-node/   CLI (init/add/get/ls/revoke/id/daemon)
apps/nv-app/ interface graphique (Tauri, desktop ; Android à venir)
```

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/noctavault/noctavault-project/main/get.sh | sh
```

Détecte la distribution (Arch, Debian/Ubuntu, Fedora, openSUSE, Alpine),
installe les dépendances système et Rust si besoin, compile et installe
`nv-node`/`nv-app` dans `~/.local/bin`. Ou, depuis un clone existant :
`./get.sh`.

Pour un serveur dédié sans interface graphique (VPS), voir `get-node.sh`
— installe uniquement `nv-node` et configure un service systemd pour le
daemon.

**Windows** (PowerShell) :

```powershell
irm https://raw.githubusercontent.com/noctavault/noctavault-project/main/get.ps1 | iex
```

Installe WebView2 et les Visual C++ Build Tools via `winget` si absents,
Rust si besoin, compile et installe `nv-node`/`nv-app` dans
`%LOCALAPPDATA%\Noctavault\bin`. ⚠️ Script non testé en conditions
réelles (pas de machine Windows disponible pour le valider) — à essayer
sur une machine propre avant de s'y fier.

## Utilisation

```bash
cargo build -p nv-node -p nv-app

# Créer son identité post-quantique
./target/debug/nv-node --home ~/.noctavault init

# Exporter son portefeuille public pour le donner à un contact
./target/debug/nv-node --home ~/.noctavault id -o moi.nvid

# Ajouter un fichier (chiffré pour soi-même, et pour des destinataires optionnels)
./target/debug/nv-node --home ~/.noctavault add mon-fichier.pdf --to alice.nvid,bob.nvid

# Lister les fichiers connus du ledger local
./target/debug/nv-node --home ~/.noctavault ls

# Récupérer un fichier depuis son manifeste
./target/debug/nv-node --home ~/.noctavault get mon-fichier.pdf.nvault

# Révoquer un fichier (purge les chunks chez tous les nœuds qui appliquent la révocation)
./target/debug/nv-node --home ~/.noctavault revoke <file_id>

# Lancer un nœud complet : écoute réseau, mDNS, sync
./target/debug/nv-node --home ~/.noctavault daemon --listen 0.0.0.0:7777 --peers 203.0.113.7:7777
```

Ou lancer l'interface graphique (disponible en français et en anglais) :

```bash
cargo run -p nv-app
```

Elle permet notamment de voir/copier sa clé publique, de partager un
fichier en collant directement la clé publique d'un destinataire (sans
passer par un fichier `.nvid`), et de sauvegarder/importer son identité
complète (clé privée) pour changer d'appareil.

## Utiliser son identité sur plusieurs appareils

L'identité (`~/.noctavault/identity.nvkey`) est **le seul moyen d'accéder
à tes fichiers** — il n'y a ni compte, ni mot de passe, ni service central.
Pour l'utiliser sur un autre appareil, **copie ce fichier** (clé USB,
`scp`, gestionnaire de mots de passe...) vers le `~/.noctavault` (ou le
`--home` choisi) de l'autre appareil, avant d'y lancer `nv-node`/`nv-app`.

```bash
scp ~/.noctavault/identity.nvkey autre-machine:.noctavault/identity.nvkey
```

⚠️ Ce fichier est une clé privée en clair : traite-le comme un
portefeuille crypto (transport chiffré/hors ligne, jamais par mail ou
messagerie non chiffrée). **Il n'existe aucune récupération possible** —
si `identity.nvkey` est perdu, tous les fichiers qui t'étaient destinés
deviennent définitivement irrécupérables. Fais-en une sauvegarde sûre dès
la création de l'identité.

## État du projet

| Brique | État |
|---|---|
| `nv-core` — crypto post-quantique, format `.nvault`/`.nvid` | ✅ |
| `nv-chain` — ledger de transactions signées, rate-limit, révocation | ✅ |
| `nv-net` — gossip, synchronisation, mDNS/PEX | ✅ |
| `nv-node` — CLI | ✅ |
| `nv-app` — interface graphique desktop | ✅ |
| Android | ⏳ |

## Limites connues

- Réplication totale : chaque nœud stocke l'intégralité du ledger. Adapté
  à la taille actuelle du projet, un sharding serait à prévoir si le
  réseau grossit beaucoup.
- Le rate-limit anti-spam est par identité ; créer une nouvelle identité
  est gratuit (juste une paire de clés), donc contournable en théorie par
  la création massive d'identités jetables (Sybil). Aucune protection
  dédiée pour l'instant.

## Licence

MIT.
