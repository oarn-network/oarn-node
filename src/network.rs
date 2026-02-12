//! P2P networking module using libp2p
//!
//! Handles peer discovery, gossipsub messaging, and DHT operations.
//! IMPORTANT: No hardcoded bootstrap nodes - all discovered via DHT/ENS/registry

use anyhow::Result;
use libp2p::{
    gossipsub, identify, kad, noise, ping, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux,
    Multiaddr, PeerId, Swarm,
};
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
#[derive(Debug, Clone)]
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
    event_tx: mpsc::Sender<NetworkEvent>,
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

        // Create transport
        let transport = tcp::tokio::Transport::default()
            .upgrade(libp2p::core::upgrade::Version::V1Lazy)
            .authenticate(noise::Config::new(&local_key)?)
            .multiplex(yamux::Config::default())
            .boxed();

        // Create gossipsub
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| anyhow::anyhow!("Gossipsub config error: {}", e))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )?;

        // Create Kademlia DHT
        let store = kad::store::MemoryStore::new(local_peer_id);
        let mut kademlia_config = kad::Config::default();
        kademlia_config.set_protocol_names(vec![
            libp2p::StreamProtocol::try_from_owned(config.network.discovery.dht_protocol.clone())
                .unwrap(),
        ]);
        let kademlia = kad::Behaviour::with_config(local_peer_id, store, kademlia_config);

        // Create identify
        let identify = identify::Behaviour::new(identify::Config::new(
            "/oarn/id/1.0.0".to_string(),
            local_key.public(),
        ));

        // Create ping
        let ping = ping::Behaviour::new(ping::Config::new());

        // Create behaviour
        let behaviour = OARNBehaviour {
            gossipsub,
            kademlia,
            identify,
            ping,
        };

        // Create swarm
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(60)),
        );

        // Listen on configured addresses
        for addr in &config.network.listen_addresses {
            let addr: Multiaddr = addr.parse()?;
            swarm.listen_on(addr)?;
        }

        // Bootstrap from discovered nodes (NOT hardcoded!)
        for node in discovery.get_bootstrap_nodes().await? {
            let addr: Multiaddr = node.multiaddr.parse()?;
            let peer_id: PeerId = node.peer_id.parse()?;

            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
            debug!("Added bootstrap node: {} at {}", peer_id, addr);
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
            event_tx,
            event_rx,
        })
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Get next network event
    pub async fn next_event(&mut self) -> Option<NetworkEvent> {
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
