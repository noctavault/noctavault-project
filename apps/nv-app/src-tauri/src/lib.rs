//! Backend Tauri : expose le nœud Noctavault à l'interface.

use nv_core::identity::{Identity, PublicIdentity};
use nv_core::{vault, Manifest};
use nv_node::Home;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use tauri::{Manager, State};

struct AppState {
    home: Home,
    identity: Identity,
    node: nv_net::Node,
    listen: String,
}

#[derive(Serialize)]
struct Status {
    node_id: String,
    tx_count: usize,
    files: usize,
    peers: Vec<String>,
    listen: String,
}

#[derive(Serialize)]
struct FileEntry {
    file_id: String,
    name: String,
    size: u64,
    chunks: usize,
    owner: String,
    mine: bool,
    created: u64,
    shared_with: Vec<String>,
    prev_version: Option<String>,
}

#[derive(Serialize)]
struct AddResult {
    manifest_path: String,
    n_chunks: usize,
    peers_notified: usize,
    shared_with: Vec<String>,
}

type CmdResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[tauri::command]
async fn status(state: State<'_, AppState>) -> CmdResult<Status> {
    let ledger = state.node.ledger.lock().await;
    let peers = state.node.peer_list().await;
    Ok(Status {
        node_id: state.identity.id(),
        tx_count: ledger.tx_count(),
        files: ledger.manifests().len(),
        peers: peers.iter().map(|p| p.to_string()).collect(),
        listen: state.listen.clone(),
    })
}

#[tauri::command]
async fn list_files(state: State<'_, AppState>) -> CmdResult<Vec<FileEntry>> {
    let my_id = state.identity.id();
    let ledger = state.node.ledger.lock().await;
    Ok(ledger
        .manifests()
        .iter()
        .map(|m| FileEntry {
            file_id: m.file_id.clone(),
            name: m.name.clone(),
            size: m.size,
            chunks: m.chunks.len(),
            owner: m.owner.id(),
            mine: m.owner.id() == my_id,
            created: m.created,
            shared_with: m
                .recipients
                .iter()
                .map(|r| r.id.clone())
                .filter(|id| *id != m.owner.id())
                .collect(),
            prev_version: m.prev_version.clone(),
        })
        .collect())
}

/// Ajoute un fichier ; `to` = chemins de portefeuilles .nvid destinataires.
#[tauri::command]
async fn add_file(
    path: String,
    to: Vec<String>,
    state: State<'_, AppState>,
) -> CmdResult<AddResult> {
    let path = PathBuf::from(path);
    let data = std::fs::read(&path).map_err(err)?;
    let name = path
        .file_name()
        .ok_or("nom de fichier invalide")?
        .to_string_lossy()
        .to_string();
    let recipients: Vec<PublicIdentity> = to
        .iter()
        .map(|p| PublicIdentity::load(std::path::Path::new(p)))
        .collect::<Result<_, _>>()
        .map_err(err)?;

    let (manifest, envelopes) = {
        let mut ledger = state.node.ledger.lock().await;
        let prev = ledger
            .manifests()
            .iter()
            .rev()
            .find(|m| m.name == name && m.owner.id() == state.identity.id())
            .map(|m| m.file_id.clone());
        // Ledger::submit fait de l'E/S disque + vérif de signature :
        // block_in_place évite de geler tout le runtime tauri (boucle de
        // fond + autres commandes) le temps de l'opération.
        tokio::task::block_in_place(|| {
            nv_node::add_to_ledger(&mut ledger, &state.identity, &data, &name, &recipients, prev)
        })
        .map_err(err)?
    };
    let manifest_path = nv_node::manifest_path_for(&path);
    manifest.save(&manifest_path).map_err(err)?;

    for envelope in envelopes {
        state.node.broadcast_envelope(envelope).await;
    }
    let n = state.node.peer_list().await.len();

    Ok(AddResult {
        manifest_path: manifest_path.display().to_string(),
        n_chunks: manifest.chunks.len(),
        peers_notified: n,
        shared_with: recipients.iter().map(|r| r.id()).collect(),
    })
}

#[tauri::command]
async fn get_file(
    manifest_path: String,
    state: State<'_, AppState>,
) -> CmdResult<String> {
    let mpath = PathBuf::from(&manifest_path);
    let manifest = Manifest::load(&mpath).map_err(err)?;
    let ledger = state.node.ledger.lock().await;
    let data = vault::decrypt(&manifest, &state.identity, |h| ledger.get_chunk(h)).map_err(err)?;
    drop(ledger);
    let out = mpath
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(nv_node::safe_out_name(&manifest));
    std::fs::write(&out, data).map_err(err)?;
    Ok(out.display().to_string())
}

/// Reconstruit un fichier publié dans le ledger, par son file_id.
#[tauri::command]
async fn get_by_id(
    file_id: String,
    out_dir: String,
    state: State<'_, AppState>,
) -> CmdResult<String> {
    let ledger = state.node.ledger.lock().await;
    let manifest = ledger
        .manifests()
        .iter()
        .find(|m| m.file_id == file_id)
        .cloned()
        .ok_or("fichier introuvable dans le ledger")?;
    let data = vault::decrypt(&manifest, &state.identity, |h| ledger.get_chunk(h)).map_err(err)?;
    drop(ledger);
    let out = PathBuf::from(out_dir).join(nv_node::safe_out_name(&manifest));
    std::fs::write(&out, data).map_err(err)?;
    Ok(out.display().to_string())
}

/// Révoque un de nos fichiers et diffuse la purge.
#[tauri::command]
async fn revoke(file_id: String, state: State<'_, AppState>) -> CmdResult<usize> {
    let envelope = {
        let mut ledger = state.node.ledger.lock().await;
        let tx = nv_chain::make_revoke(&file_id, &state.identity).map_err(err)?;
        let envelope = nv_chain::Envelope::new(tx, &state.identity).map_err(err)?;
        tokio::task::block_in_place(|| ledger.submit(envelope.clone())).map_err(err)?;
        envelope
    };
    state.node.broadcast_envelope(envelope).await;
    Ok(state.node.ledger.lock().await.tx_count())
}

/// Exporte le portefeuille public .nvid vers `out_path`.
#[tauri::command]
async fn export_wallet(out_path: String, state: State<'_, AppState>) -> CmdResult<String> {
    state
        .identity
        .public
        .save(std::path::Path::new(&out_path))
        .map_err(err)?;
    Ok(out_path)
}

#[tauri::command]
async fn set_peers(peers: Vec<String>, state: State<'_, AppState>) -> CmdResult<Vec<String>> {
    let parsed: Result<Vec<SocketAddr>, _> = peers.iter().map(|p| p.parse()).collect();
    let parsed = parsed.map_err(|_| "format attendu : hôte:port".to_string())?;
    let mut config = state.home.load_config().map_err(err)?;
    config.peers = peers.clone();
    state.home.save_config(&config).map_err(err)?;
    let mut set = state.node.peers.lock().await;
    for p in parsed {
        set.insert(p);
    }
    Ok(peers)
}

#[tauri::command]
async fn sync_now(state: State<'_, AppState>) -> CmdResult<usize> {
    state.node.sync_once().await.map_err(err)?;
    Ok(state.node.ledger.lock().await.tx_count())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let home = Home::new(None)?;
            let (identity, _) = home.init_identity()?;
            let ledger = home.open_ledger()?;
            let config = home.load_config()?;
            let peers = home.peers()?;
            let listen = config.listen.clone().unwrap_or_else(|| "0.0.0.0:7777".into());

            let node = nv_net::Node::new(ledger, peers);
            let state = AppState {
                home,
                identity: identity.clone(),
                node: node.clone(),
                listen: listen.clone(),
            };
            app.manage(state);

            // Écoute réseau, mDNS et synchronisation périodique en fond.
            tauri::async_runtime::spawn(async move {
                let mut _mdns = None;
                if let Ok(addr) = listen.parse::<SocketAddr>() {
                    match node.listen(addr).await {
                        Ok(bound) => {
                            eprintln!("noctavault : écoute sur {bound}");
                            _mdns = node.start_mdns(bound.port()).ok();
                        }
                        Err(e) => {
                            eprintln!("noctavault : écoute impossible ({e}), mode client seul")
                        }
                    }
                }
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    // Rattrapage des enveloppes écrites directement sur le
                    // disque par un autre processus (CLI `nv-node add`/
                    // `revoke` sur le même --home) : adressées par contenu,
                    // plus besoin de verrou inter-processus, juste relire
                    // `txs/` pour rattraper les nouvelles.
                    {
                        let mut ledger = node.ledger.lock().await;
                        let _ = tokio::task::block_in_place(|| ledger.refresh());
                    }
                    let _ = node.sync_once().await;
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status, list_files, add_file, get_file, get_by_id, revoke, export_wallet,
            set_peers, sync_now
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de Noctavault");
}
