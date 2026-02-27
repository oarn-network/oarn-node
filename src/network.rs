//! P2P networking module using libp2p
//!
//! Handles peer discovery, gossipsub messaging, and DHT operations.
//! Uses mDNS for local discovery and DHT for wide-area peer finding.

use anyhow::Result;
use libp2p::{
    gossipsub, identify, kad, mdns, noise, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::discovery::Discovery;

/// Network events emitted to the main loop
#[derive(Debug)]
pub enum NetworkEvent {
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    TaskAnnounced(TaskAnnouncement),
    ResultReceived(u64, Vec<u8>),
}

/// Task announcement received via gossipsub
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskAnnouncement {
    pub id: u64,
    pub model_hash: String,
    pub input_hash: String,
    pub reward: u64,
    pub required_nodes: u32,
    pub deadline: u64,
}

/// Combined network behaviour
#[derive(NetworkBehaviour)]
pub struct OARNBehaviour {
    gossipsub: gossipsub::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

/// P2P Network manager
pub struct P2PNetwork {
    swarm: Swarm<OARNBehaviour>,
    _event_tx: mpsc::Sender<NetworkEvent>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    discovered_peers: HashSet<PeerId>,
    bootstrap_complete: bool,
}

impl P2PNetwork {
    /// Create a new P2P network instance
    pub async fn new(config: &Config, discovery: &Discovery) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::channel(100);

        // Generate or load keypair
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        info!("Local peer ID: {}", local_peer_id);

        // Create swarm with tokio runtime
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                // Create gossipsub
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(10))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .build()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                // Create Kademlia DHT with OARN protocol
                let store = kad::store::MemoryStore::new(local_peer_id);
                let mut kademlia_config = kad::Config::default();
                // Set a longer record TTL for bootstrap info
                kademlia_config.set_record_ttl(Some(Duration::from_secs(3600)));
                kademlia_config.set_replication_interval(Some(Duration::from_secs(300)));
                let kademlia = kad::Behaviour::with_config(local_peer_id, store, kademlia_config);

                // Create identify
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/oarn/id/1.0.0".to_string(),
                    key.public(),
                ));

                // Create ping
                let ping = ping::Behaviour::new(ping::Config::new());

                // Create mDNS for local network discovery
                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    local_peer_id,
                ).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                Ok(OARNBehaviour {
                    gossipsub,
                    kademlia,
                    identify,
                    ping,
                    mdns,
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
            .build();

        // Listen on configured addresses
        for addr in &config.network.listen_addresses {
            let addr: Multiaddr = addr.parse()?;
            swarm.listen_on(addr)?;
        }

        // Count bootstrap nodes added
        let mut bootstrap_count = 0;

        // Bootstrap from discovered nodes
        for node in discovery.get_bootstrap_nodes().await? {
            if let (Ok(addr), Ok(peer_id)) = (
                node.multiaddr.parse::<Multiaddr>(),
                node.peer_id.parse::<PeerId>(),
            ) {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                info!("Added bootstrap node: {} at {}", peer_id, addr);
                bootstrap_count += 1;

                // Also try to dial the bootstrap node directly
                if let Err(e) = swarm.dial(addr.clone()) {
                    debug!("Failed to dial bootstrap {}: {}", peer_id, e);
                }
            }
        }

        // Start DHT bootstrap if we have peers
        let bootstrap_complete = if bootstrap_count > 0 {
            match swarm.behaviour_mut().kademlia.bootstrap() {
                Ok(_) => {
                    info!("DHT bootstrap initiated with {} nodes", bootstrap_count);
                    false // Will be set to true when bootstrap completes
                }
                Err(e) => {
                    warn!("DHT bootstrap failed: {}", e);
                    false
                }
            }
        } else {
            info!("No bootstrap nodes configured - using mDNS for local discovery");
            info!("Waiting for peers via mDNS or incoming connections...");
            false
        };

        // Subscribe to task announcements topic
        let topic = gossipsub::IdentTopic::new("oarn/tasks/v1");
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        // Also subscribe to network coordination topic
        let coord_topic = gossipsub::IdentTopic::new("oarn/network/v1");
        swarm.behaviour_mut().gossipsub.subscribe(&coord_topic)?;

        Ok(Self {
            swarm,
            _event_tx: event_tx,
            event_rx,
            discovered_peers: HashSet::new(),
            bootstrap_complete,
        })
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Get next network event
    pub async fn next_event(&mut self) -> Option<NetworkEvent> {
        use futures::StreamExt;

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    if let Some(network_event) = self.handle_swarm_event(event).await {
                        return Some(network_event);
                    }
                }
                event = self.event_rx.recv() => {
                    return event;
                }
            }
        }
    }

    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<OARNBehaviourEvent>,
    ) -> Option<NetworkEvent> {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.discovered_peers.insert(peer_id);
                info!("Connected to peer: {} (total: {})", peer_id, self.discovered_peers.len());

                // Add peer to Kademlia if not already known
                // The identify protocol will provide addresses

                Some(NetworkEvent::PeerConnected(peer_id))
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.discovered_peers.remove(&peer_id);
                info!("Disconnected from peer: {} (remaining: {})", peer_id, self.discovered_peers.len());
                Some(NetworkEvent::PeerDisconnected(peer_id))
            }
            SwarmEvent::Behaviour(OARNBehaviourEvent::Gossipsub(
                gossipsub::Event::Message { message, .. },
            )) => {
                // Parse task announcement
                if let Ok(task) = serde_json::from_slice::<TaskAnnouncement>(&message.data) {
                    return Some(NetworkEvent::TaskAnnounced(task));
                }
                None
            }
            SwarmEvent::Behaviour(OARNBehaviourEvent::Kademlia(event)) => {
                self.handle_kademlia_event(event);
                None
            }
            SwarmEvent::Behaviour(OARNBehaviourEvent::Mdns(event)) => {
                self.handle_mdns_event(event);
                None
            }
            SwarmEvent::Behaviour(OARNBehaviourEvent::Identify(event)) => {
                self.handle_identify_event(event);
                None
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on: {}", address);
                None
            }
            _ => None,
        }
    }

    /// Handle Kademlia DHT events
    fn handle_kademlia_event(&mut self, event: kad::Event) {
        match event {
            kad::Event::RoutingUpdated { peer, is_new_peer, .. } => {
                if is_new_peer {
                    info!("New peer added to DHT: {}", peer);
                } else {
                    debug!("DHT routing updated: {}", peer);
                }
            }
            kad::Event::OutboundQueryProgressed { result, .. } => {
                match result {
                    kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { num_remaining, .. })) => {
                        if num_remaining == 0 {
                            info!("DHT bootstrap complete!");
                            self.bootstrap_complete = true;
                        } else {
                            debug!("DHT bootstrap progress: {} remaining", num_remaining);
                        }
                    }
                    kad::QueryResult::Bootstrap(Err(e)) => {
                        warn!("DHT bootstrap error: {:?}", e);
                    }
                    kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                        info!("Found {} closest peers", ok.peers.len());
                        for peer in ok.peers {
                            self.discovered_peers.insert(peer);
                        }
                    }
                    _ => {}
                }
            }
            kad::Event::RoutablePeer { peer, address } => {
                info!("Discovered routable peer: {} at {}", peer, address);
            }
            _ => {}
        }
    }

    /// Handle mDNS local discovery events
    fn handle_mdns_event(&mut self, event: mdns::Event) {
        match event {
            mdns::Event::Discovered(peers) => {
                for (peer_id, addr) in peers {
                    if !self.discovered_peers.contains(&peer_id) {
                        info!("mDNS discovered peer: {} at {}", peer_id, addr);

                        // Add to Kademlia
                        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());

                        // Try to dial the peer
                        if let Err(e) = self.swarm.dial(addr.clone()) {
                            debug!("Failed to dial mDNS peer {}: {}", peer_id, e);
                        }

                        // Try bootstrap again if we weren't connected before
                        if !self.bootstrap_complete && self.discovered_peers.is_empty() {
                            if let Err(e) = self.swarm.behaviour_mut().kademlia.bootstrap() {
                                debug!("DHT bootstrap retry failed: {}", e);
                            }
                        }
                    }
                }
            }
            mdns::Event::Expired(peers) => {
                for (peer_id, _addr) in peers {
                    debug!("mDNS peer expired: {}", peer_id);
                }
            }
        }
    }

    /// Handle identify protocol events
    fn handle_identify_event(&mut self, event: identify::Event) {
        match event {
            identify::Event::Received { peer_id, info } => {
                debug!("Identified peer {}: {} with {} addresses",
                       peer_id, info.protocol_version, info.listen_addrs.len());

                // Add all addresses to Kademlia
                for addr in info.listen_addrs {
                    self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                }

                // Add peer to gossipsub
                self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
            }
            identify::Event::Sent { peer_id } => {
                debug!("Sent identify info to {}", peer_id);
            }
            _ => {}
        }
    }

    /// Broadcast a task announcement
    pub fn announce_task(&mut self, task: &TaskAnnouncement) -> Result<()> {
        let topic = gossipsub::IdentTopic::new("oarn/tasks/v1");
        let data = serde_json::to_vec(task)?;

        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, data)?;

        Ok(())
    }

    /// Get connected peer count
    pub fn peer_count(&self) -> usize {
        self.swarm.connected_peers().count()
    }

    /// Get all discovered peers (connected and known)
    pub fn discovered_peers(&self) -> &HashSet<PeerId> {
        &self.discovered_peers
    }

    /// Check if DHT bootstrap is complete
    pub fn is_bootstrap_complete(&self) -> bool {
        self.bootstrap_complete
    }

    /// Trigger a DHT peer lookup to discover more nodes
    pub fn find_peers(&mut self) {
        // Query for random peer IDs to discover more nodes
        let random_peer = PeerId::random();
        self.swarm.behaviour_mut().kademlia.get_closest_peers(random_peer);
        debug!("Initiated DHT peer discovery");
    }

    /// Add a peer address to the DHT
    pub fn add_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
        info!("Added peer to DHT: {} at {}", peer_id, addr);

        // Try to dial the peer
        if let Err(e) = self.swarm.dial(addr) {
            debug!("Failed to dial peer {}: {}", peer_id, e);
        }
    }

    /// Dial a specific multiaddress
    pub fn dial(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.dial(addr)?;
        Ok(())
    }

    /// Get network statistics
    pub fn stats(&self) -> NetworkStats {
        NetworkStats {
            connected_peers: self.swarm.connected_peers().count(),
            discovered_peers: self.discovered_peers.len(),
            bootstrap_complete: self.bootstrap_complete,
        }
    }
}

/// Network statistics
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub connected_peers: usize,
    pub discovered_peers: usize,
    pub bootstrap_complete: bool,
}
