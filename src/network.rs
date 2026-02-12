//! P2P networking module using libp2p
//!
//! Handles peer discovery, gossipsub messaging, and DHT operations.
//! IMPORTANT: No hardcoded bootstrap nodes - all discovered via DHT/ENS/registry

use anyhow::Result;
use libp2p::{
    gossipsub, identify, kad, noise, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, StreamProtocol,
};
use serde::{Deserialize, Serialize};
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
}

/// P2P Network manager
pub struct P2PNetwork {
    swarm: Swarm<OARNBehaviour>,
    _event_tx: mpsc::Sender<NetworkEvent>,
    event_rx: mpsc::Receiver<NetworkEvent>,
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

                // Create Kademlia DHT with default protocol
                let store = kad::store::MemoryStore::new(local_peer_id);
                let kademlia_config = kad::Config::default();
                let kademlia = kad::Behaviour::with_config(local_peer_id, store, kademlia_config);

                // Create identify
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/oarn/id/1.0.0".to_string(),
                    key.public(),
                ));

                // Create ping
                let ping = ping::Behaviour::new(ping::Config::new());

                Ok(OARNBehaviour {
                    gossipsub,
                    kademlia,
                    identify,
                    ping,
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Listen on configured addresses
        for addr in &config.network.listen_addresses {
            let addr: Multiaddr = addr.parse()?;
            swarm.listen_on(addr)?;
        }

        // Bootstrap from discovered nodes (NOT hardcoded!)
        for node in discovery.get_bootstrap_nodes().await? {
            if let (Ok(addr), Ok(peer_id)) = (
                node.multiaddr.parse::<Multiaddr>(),
                node.peer_id.parse::<PeerId>(),
            ) {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                debug!("Added bootstrap node: {} at {}", peer_id, addr);
            }
        }

        // Start DHT bootstrap
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            warn!("DHT bootstrap failed (may need more peers): {}", e);
        }

        // Subscribe to task announcements topic
        let topic = gossipsub::IdentTopic::new("oarn/tasks/v1");
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        Ok(Self {
            swarm,
            _event_tx: event_tx,
            event_rx,
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
                info!("Connected to peer: {}", peer_id);
                Some(NetworkEvent::PeerConnected(peer_id))
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Disconnected from peer: {}", peer_id);
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
            SwarmEvent::Behaviour(OARNBehaviourEvent::Kademlia(
                kad::Event::RoutingUpdated { peer, .. },
            )) => {
                debug!("DHT routing updated: {}", peer);
                None
            }
            _ => None,
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
}
