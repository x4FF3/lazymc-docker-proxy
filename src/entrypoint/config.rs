use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env::var;
use std::fs::File;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::process::{exit, Command};
use version_compare::Version;

use crate::{docker, health};

const DEFAULT_PORT: i32 = 25565;

/// lazymc dropped support minecraft servers with version less than 1.20.3
fn is_legacy(version: Option<String>) -> bool {
    if version.is_none() {
        return false;
    }

    Version::from(version.unwrap().as_ref()) < Version::from("1.20.3")
}

#[derive(Serialize, Deserialize)]
struct ServerSection {
    address: Option<String>,
    block_banned_ips: Option<bool>,
    command: Option<String>,
    directory: Option<String>,
    drop_banned_ips: Option<bool>,
    forge: Option<bool>,
    freeze_process: Option<bool>,
    probe_on_start: Option<bool>,
    send_proxy_v2: Option<bool>,
    start_timeout: Option<i32>,
    stop_timeout: Option<i32>,
    wake_on_crash: Option<bool>,
    wake_on_start: Option<bool>,
    wake_whitelist: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct PublicSection {
    address: Option<String>,
    version: Option<String>,
    protocol: Option<i32>,
}

#[derive(Serialize, Deserialize)]
struct TimeSection {
    minimum_online_time: Option<i32>,
    sleep_after: Option<i32>,
}

#[derive(Serialize, Deserialize)]
struct JoinSection {
    methods: Option<Vec<String>>,
    kick: JoinKickSection,
    hold: JoinHoldSection,
    forward: JoinForwardSection,
    lobby: JoinLobbySection,
}

#[derive(Serialize, Deserialize, Clone)]
struct JoinKickSection {
    starting: Option<String>,
    stopping: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct JoinHoldSection {
    timeout: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone)]
struct JoinForwardSection {
    address: Option<String>,
    send_proxy_v2: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone)]
struct JoinLobbySection {
    timeout: Option<i32>,
    message: Option<String>,
    ready_sound: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct MotdSection {
    sleeping: Option<String>,
    starting: Option<String>,
    stopping: Option<String>,
    from_server: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct LockoutSection {
    enabled: Option<bool>,
    message: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct AdvancedSection {
    rewrite_server_properties: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct ConfigSection {
    version: Option<String>,
}

/// An additional port lazymc holds and forwards while the server sleeps.
///
/// Serialized as a TOML array of tables (`[[forward]]`). Used for sidecar
/// services living inside the Minecraft container, GeyserMC above all, whose
/// ports go down together with the server.
#[derive(Serialize, Deserialize, Clone)]
struct ForwardSection {
    public: String,
    server: String,
    proto: Option<String>,
    wake: Option<bool>,
    session_timeout: Option<i32>,
    bedrock_version: Option<String>,
    bedrock_protocol: Option<i32>,
}

/// Accepted values for `lazymc.forward.<name>.proto`.
const FORWARD_PROTOS: [&str; 3] = ["bedrock", "tcp", "udp"];

/// Protocol assumed when a forward rule does not name one.
///
/// This feature exists for GeyserMC above all, so the RakNet-aware variant is
/// the least surprising default.
const FORWARD_PROTO_DEFAULT: &str = "bedrock";

/// Resolve a forward target to an IPv4 `host:port`, keeping the literal on failure.
///
/// Mirrors how `lazymc.server.address` is handled: the Minecraft container may
/// well be stopped while this runs, and then its name does not resolve yet.
fn resolve_forward_address(name: &str, address: &str) -> String {
    address
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.find(|addr| addr.is_ipv4()))
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| {
            warn!(target: "lazymc-docker-proxy::entrypoint::config", "Failed to resolve IP address from lazymc.forward.{}.server. Falling back to the value provided.", name);
            address.to_string()
        })
}

/// Collect `[[forward]]` rules from `lazymc.forward.<name>.<field>` labels.
///
/// The rule name only groups the labels of one rule together, it never reaches
/// the generated config. `lazymc.join.forward.*` cannot collide with this: it
/// does not carry the `lazymc.forward.` prefix.
fn forward_sections(labels: &HashMap<String, String>) -> Vec<ForwardSection> {
    let mut names: Vec<String> = labels
        .keys()
        .filter_map(|key| key.strip_prefix("lazymc.forward."))
        .filter_map(|rest| rest.split('.').next())
        .filter(|name| !name.is_empty())
        .map(|name| name.to_string())
        .collect();
    names.sort_unstable();
    names.dedup();

    names
        .into_iter()
        .map(|name| {
            let field = |field: &str| labels.get(&format!("lazymc.forward.{}.{}", name, field));

            let server: String = field("server")
                .cloned()
                .unwrap_or_else(|| {
                    error!(target: "lazymc-docker-proxy::entrypoint::config", "lazymc.forward.{}.server is not set", name);
                    health::unhealthy();
                    exit(1);
                });

            // The port has to be pinned here already: it is what the public
            // address falls back to, and lazymc rejects a bare host anyway
            let port: u16 = server
                .rsplit(':')
                .next()
                .and_then(|port| port.parse().ok())
                .unwrap_or_else(|| {
                    error!(target: "lazymc-docker-proxy::entrypoint::config", "lazymc.forward.{}.server must be in host:port form, got '{}'", name, server);
                    health::unhealthy();
                    exit(1);
                });

            let proto: String = field("proto")
                .cloned()
                .unwrap_or_else(|| FORWARD_PROTO_DEFAULT.to_string());
            if !FORWARD_PROTOS.contains(&proto.as_str()) {
                error!(target: "lazymc-docker-proxy::entrypoint::config", "lazymc.forward.{}.proto must be one of {:?}, got '{}'", name, FORWARD_PROTOS, proto);
                health::unhealthy();
                exit(1);
            }

            ForwardSection {
                public: field("public")
                    .cloned()
                    .unwrap_or_else(|| format!("0.0.0.0:{}", port)),
                server: resolve_forward_address(&name, &server),
                proto: Some(proto),
                wake: field("wake").map(|wake| wake == "true"),
                session_timeout: field("session_timeout").and_then(|x| x.parse().ok()),
                bedrock_version: field("bedrock_version").cloned(),
                bedrock_protocol: field("bedrock_protocol").and_then(|x| x.parse().ok()),
            }
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    advanced: AdvancedSection,
    config: ConfigSection,
    // must serialize as an empty-skipped array: a bare `forward = []` emitted
    // after the section tables above would make toml::to_string fail
    #[serde(skip_serializing_if = "Vec::is_empty")]
    forward: Vec<ForwardSection>,
    join: JoinSection,
    lockout: LockoutSection,
    motd: MotdSection,
    public: PublicSection,
    server: ServerSection,
    time: TimeSection,
    #[serde(skip)]
    start_command: String,
    #[serde(skip)]
    config_file: String,
    #[serde(skip)]
    group: String,
    #[serde(skip)]
    resolved_ip: bool,
}

/// Configuration for the lazymc server
impl Config {
    /// Generate the start command for the lazymc server
    pub fn start_command(&self) -> Command {
        // Start the docker container if the IP address has not been resolved
        if !self.resolved_ip {
            docker::start(self.group().into());
        }

        let mut command: Command = Command::new(self.start_command.clone());
        command.arg("start");
        command.arg("--config");
        command.arg(self.config_file.clone());
        command
    }

    /// Get the group name for the lazymc server
    pub fn group(&self) -> &str {
        &self.group
    }

    /// Convert the configuration to a TOML string
    fn as_toml_string(&self) -> String {
        toml::to_string(self).unwrap()
    }

    /// Create the lazymc configuration file
    fn create_file(&self) {
        let toml = self.as_toml_string();
        let file_name: &String = &format!("lazymc.{}.toml", self.group.clone());
        let path: &Path = Path::new(file_name);
        let mut file = File::create(path).unwrap();
        file.write_all(toml.as_ref()).unwrap();
        debug!(target: "lazymc-docker-proxy::entrypoint::config", "`generated`: {}\n\n{}", path.display(), toml);
    }

    /// Create a new configuration from container labels
    pub fn from_container_labels(labels: HashMap<String, String>) -> Self {
        // Check for required labels
        labels.get("lazymc.server.address").unwrap_or_else(|| {
            error!(target: "lazymc-docker-proxy::entrypoint::config", "lazymc.server.address is not set");
            health::unhealthy();
            exit(1);
        });
        labels.get("lazymc.group").unwrap_or_else(|| {
            error!(target: "lazymc-docker-proxy::entrypoint::config", "lazymc.group is not set");
            health::unhealthy();
            exit(1);
        });

        // Check if the IP address has been resolved
        let mut resolved_ip = true;

        let server_section: ServerSection = ServerSection {
            address: labels.get("lazymc.server.address")
                .and_then(|address| address.to_socket_addrs().ok())
                .and_then(|mut addrs| addrs.find(|addr| addr.is_ipv4()))
                .and_then(|addr| addr.to_string().parse().ok())
                .or_else(|| {
                    warn!(target: "lazymc-docker-proxy::entrypoint::config", "Failed to resolve IP address from lazymc.server.address. Falling back to the value provided.");
                    resolved_ip = false;
                    labels.get("lazymc.server.address").cloned()
                }),
            directory: Some(
                labels
                    .get("lazymc.server.directory")
                    .cloned()
                    .unwrap_or_else(|| "/server".to_string()),
            ),
            command: Some(format!(
                "lazymc-docker-proxy --command --group {}",
                labels.get("lazymc.group").unwrap()
            )),
            freeze_process: Some(false),
            // If the IP address was not resolved, wake_on_start should be true
            wake_on_start: Some(!resolved_ip),
            wake_on_crash: Some(true),
            wake_whitelist: labels
                .get("lazymc.server.wake_whitelist")
                .map(|x| x == "true"),
            block_banned_ips: labels
                .get("lazymc.server.block_banned_ips")
                .map(|x| x == "true"),
            drop_banned_ips: labels
                .get("lazymc.server.drop_banned_ips")
                .map(|x| x == "true"),
            probe_on_start: labels
                .get("lazymc.server.probe_on_start")
                .map(|x| x == "true"),
            forge: labels.get("lazymc.server.forge").map(|x| x == "true"),
            start_timeout: labels
                .get("lazymc.server.start_timeout")
                .and_then(|x| x.parse().ok()),
            stop_timeout: labels
                .get("lazymc.server.stop_timeout")
                .and_then(|x| x.parse().ok()),
            send_proxy_v2: labels
                .get("lazymc.server.send_proxy_v2")
                .map(|x| x == "true"),
        };

        let time_section: TimeSection = TimeSection {
            sleep_after: labels
                .get("lazymc.time.sleep_after")
                .and_then(|x| x.parse().ok()),
            minimum_online_time: labels
                .get("lazymc.time.minimum_online_time")
                .and_then(|x| x.parse().ok()),
        };

        let join_kick_section: JoinKickSection = JoinKickSection {
            starting: labels.get("lazymc.join.kick.starting").cloned(),
            stopping: labels.get("lazymc.join.kick.stopping").cloned(),
        };

        let join_hold_section: JoinHoldSection = JoinHoldSection {
            timeout: labels
                .get("lazymc.join.hold.timeout")
                .and_then(|x| x.parse().ok()),
        };

        let join_forward_section: JoinForwardSection = JoinForwardSection {
            address: labels.get("lazymc.join.forward.address").cloned(),
            send_proxy_v2: labels
                .get("lazymc.join.forward.send_proxy_v2")
                .map(|x| x == "true"),
        };

        let join_lobby_section: JoinLobbySection = JoinLobbySection {
            timeout: labels
                .get("lazymc.join.lobby.timeout")
                .and_then(|x| x.parse().ok()),
            message: labels.get("lazymc.join.lobby.message").cloned(),
            ready_sound: labels.get("lazymc.join.lobby.sound").cloned(),
        };

        let join_section: JoinSection = JoinSection {
            methods: labels
                .get("lazymc.join.methods")
                .and_then(|x| {
                    Some(x.split(",").map(|s| s.to_string()).collect())
                        .filter(|m: &Vec<String>| !m.is_empty())
                })
                .or(None),
            kick: join_kick_section.clone(),
            hold: join_hold_section.clone(),
            forward: join_forward_section.clone(),
            lobby: join_lobby_section.clone(),
        };

        let public_section: PublicSection = PublicSection {
            address: Some(format!(
                "0.0.0.0:{}",
                labels
                    .get("lazymc.port")
                    .cloned()
                    .unwrap_or_else(|| DEFAULT_PORT.to_string())
            )),
            version: labels.get("lazymc.public.version").cloned(),
            protocol: labels
                .get("lazymc.public.protocol")
                .and_then(|x| x.parse().ok()),
        };

        let motd_section: MotdSection = MotdSection {
            sleeping: labels.get("lazymc.motd.sleeping").cloned(),
            starting: labels.get("lazymc.motd.starting").cloned(),
            stopping: labels.get("lazymc.motd.stopping").cloned(),
            from_server: labels.get("lazymc.motd.from_server").map(|x| x == "true"),
        };

        let lockout_section: LockoutSection = LockoutSection {
            enabled: labels.get("lazymc.lockout.enabled").map(|x| x == "true"),
            message: labels.get("lazymc.lockout.message").cloned(),
        };

        let advanced_section: AdvancedSection = AdvancedSection {
            rewrite_server_properties: Some(false),
        };

        let config_section: ConfigSection = ConfigSection {
            version: match is_legacy(labels.get("lazymc.public.version").cloned()) {
                true => var("LAZYMC_LEGACY_VERSION")
                    .unwrap_or_else(|err| {
                        error!(target: "lazymc-docker-proxy::entrypoint::config", "LAZYMC_LEGACY_VERSION is not set: {}", err);
                        health::unhealthy();
                        exit(1);
                    })
                    .into(),
                false => var("LAZYMC_VERSION")
                    .unwrap_or_else(|err| {
                        error!(target: "lazymc-docker-proxy::entrypoint::config", "LAZYMC_VERSION is not set: {}", err);
                        health::unhealthy();
                        exit(1);
                    })
                    .into(),
            },
        };

        let config: Config = Config {
            server: server_section,
            public: public_section,
            time: time_section,
            join: join_section,
            motd: motd_section,
            lockout: lockout_section,
            advanced: advanced_section,
            config: config_section,
            forward: forward_sections(&labels),
            start_command: match is_legacy(labels.get("lazymc.public.version").cloned()) {
                true => "lazymc-legacy".to_string(),
                false => "lazymc".to_string(),
            },
            config_file: format!(
                "lazymc.{}.toml",
                labels.get("lazymc.group").unwrap().clone()
            ),
            group: labels.get("lazymc.group").unwrap().clone(),
            resolved_ip,
        };

        // Generate the lazymc config file
        config.create_file();

        config
    }

    /// Create a new configuration from environment variables
    ///
    /// # Deprecated
    #[deprecated(since = "2.1.0", note = "Use `from_container_labels` instead")]
    pub fn from_env() -> Self {
        warn!(target: "lazymc-docker-proxy::entrypoint::config", "***************************************************************************************************************");
        warn!(target: "lazymc-docker-proxy::entrypoint::config", "DEPRECATED: Using Environment Variables to configure lazymc is deprecated. Please use container labels instead.");
        warn!(target: "lazymc-docker-proxy::entrypoint::config", "       see: https://github.com/joesturge/lazymc-docker-proxy?tab=readme-ov-file#usage");
        warn!(target: "lazymc-docker-proxy::entrypoint::config", "***************************************************************************************************************");

        let mut labels: HashMap<String, String> = HashMap::new();
        if let Ok(value) = var("LAZYMC_GROUP") {
            labels.insert("lazymc.group".to_string(), value.clone());
            // Stop the server container if it is running
            docker::stop(value.clone())
        }
        if let Ok(value) = var("LAZYMC_JOIN_METHODS") {
            labels.insert("lazymc.join.methods".to_string(), value);
        }
        if let Ok(value) = var("LAZYMC_JOIN_KICK_STARTING") {
            labels.insert("lazymc.join.kick.starting".to_string(), value);
        }
        if let Ok(value) = var("LAZYMC_JOIN_KICK_STOPPING") {
            labels.insert("lazymc.join.kick.stopping".to_string(), value);
        }
        if let Ok(value) = var("LAZYMC_JOIN_HOLD_TIMEOUT") {
            labels.insert("lazymc.join.hold.timeout".to_string(), value);
        }
        if let Ok(value) = var("LAZYMC_JOIN_FORWARD_ADDRESS") {
            labels.insert("lazymc.join.forward.address".to_string(), value);
        }
        if let Ok(value) = var("LAZYMC_JOIN_FORWARD_SEND_PROXY_V2") {
            labels.insert("lazymc.join.forward.send_proxy_v2".to_string(), value);
        }
        if let Ok(value) = var("LAZYMC_JOIN_LOBBY_TIMEOUT") {
            labels.insert("lazymc.join.lobby.timeout".to_string(), value);
        }
        if let Ok(value) = var("LAZYMC_JOIN_LOBBY_MESSAGE") {
            labels.insert("lazymc.join.lobby.message".to_string(), value);
        }
        if let Ok(value) = var("LAZYMC_JOIN_LOBBY_READY_SOUND") {
            labels.insert("lazymc.join.lobby.ready_sound".to_string(), value);
        }
        if let Ok(value) = var("LAZYMC_LOCKOUT_ENABLED") {
            labels.insert("lazymc.lockout.enabled".to_string(), value);
        }
        if let Ok(value) = var("LAZYMC_LOCKOUT_MESSAGE") {
            labels.insert("lazymc.lockout.message".to_string(), value);
        }
        if let Ok(value) = var("LAZYMC_PORT") {
            labels.insert("lazymc.port".to_string(), value);
        }
        if let Ok(value) = var("MOTD_SLEEPING") {
            labels.insert("lazymc.motd.sleeping".to_string(), value);
        }
        if let Ok(value) = var("MOTD_STARTING") {
            labels.insert("lazymc.motd.starting".to_string(), value);
        }
        if let Ok(value) = var("MOTD_STOPPING") {
            labels.insert("lazymc.motd.stopping".to_string(), value);
        }
        if let Ok(value) = var("MOTD_FROM_SERVER") {
            labels.insert("lazymc.motd.from_server".to_string(), value);
        }
        if let Ok(value) = var("PUBLIC_PROTOCOL") {
            labels.insert("lazymc.public.protocol".to_string(), value);
        }
        if let Ok(value) = var("PUBLIC_VERSION") {
            labels.insert("lazymc.public.version".to_string(), value);
        }
        if let Ok(value) = var("SERVER_ADDRESS") {
            labels.insert("lazymc.server.address".to_string(), value);
        }
        if let Ok(value) = var("SERVER_BLOCK_BANNED_IPS") {
            labels.insert("lazymc.server.block_banned_ips".to_string(), value);
        }
        if let Ok(value) = var("SERVER_DIRECTORY") {
            labels.insert("lazymc.server.directory".to_string(), value);
        }
        if let Ok(value) = var("SERVER_DROP_BANNED_IPS") {
            labels.insert("lazymc.server.drop_banned_ips".to_string(), value);
        }
        if let Ok(value) = var("SERVER_FORGE") {
            labels.insert("lazymc.server.forge".to_string(), value);
        }
        if let Ok(value) = var("SERVER_PROBE_ON_START") {
            labels.insert("lazymc.server.probe_on_start".to_string(), value);
        }
        if let Ok(value) = var("SERVER_SEND_PROXY_V2") {
            labels.insert("lazymc.server.send_proxy_v2".to_string(), value);
        }
        if let Ok(value) = var("SERVER_START_TIMEOUT") {
            labels.insert("lazymc.server.start_timeout".to_string(), value);
        }
        if let Ok(value) = var("SERVER_STOP_TIMEOUT") {
            labels.insert("lazymc.server.stop_timeout".to_string(), value);
        }
        if let Ok(value) = var("SERVER_WAKE_WHITELIST") {
            labels.insert("lazymc.server.wake_whitelist".to_string(), value);
        }
        if let Ok(value) = var("TIME_MINIMUM_ONLINE_TIME") {
            labels.insert("lazymc.time.minimum_online_time".to_string(), value);
        }
        if let Ok(value) = var("TIME_SLEEP_AFTER") {
            labels.insert("lazymc.time.sleep_after".to_string(), value);
        }

        Config::from_container_labels(labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn forward_labels_are_grouped_into_one_rule_per_name() {
        let sections = forward_sections(&labels(&[
            ("lazymc.forward.geyser.server", "127.0.0.1:19132"),
            ("lazymc.forward.geyser.bedrock_version", "1.21.0"),
            ("lazymc.forward.geyser.bedrock_protocol", "685"),
            ("lazymc.forward.voice.server", "127.0.0.1:24454"),
            ("lazymc.forward.voice.proto", "udp"),
            ("lazymc.forward.voice.wake", "false"),
            ("lazymc.forward.voice.session_timeout", "60"),
        ]));

        assert_eq!(sections.len(), 2);

        // sorted by rule name, so geyser comes first
        assert_eq!(sections[0].proto.as_deref(), Some("bedrock"));
        assert_eq!(sections[0].bedrock_version.as_deref(), Some("1.21.0"));
        assert_eq!(sections[0].bedrock_protocol, Some(685));
        assert_eq!(sections[0].wake, None);

        assert_eq!(sections[1].proto.as_deref(), Some("udp"));
        assert_eq!(sections[1].wake, Some(false));
        assert_eq!(sections[1].session_timeout, Some(60));
    }

    #[test]
    fn forward_public_defaults_to_the_server_port_on_all_interfaces() {
        let sections = forward_sections(&labels(&[(
            "lazymc.forward.geyser.server",
            "127.0.0.1:19132",
        )]));

        assert_eq!(sections[0].public, "0.0.0.0:19132");
        assert_eq!(sections[0].server, "127.0.0.1:19132");
    }

    #[test]
    fn forward_public_is_taken_verbatim_when_given() {
        let sections = forward_sections(&labels(&[
            ("lazymc.forward.geyser.server", "127.0.0.1:19132"),
            ("lazymc.forward.geyser.public", "0.0.0.0:19133"),
        ]));

        assert_eq!(sections[0].public, "0.0.0.0:19133");
    }

    #[test]
    fn join_forward_labels_are_not_mistaken_for_forward_rules() {
        let sections = forward_sections(&labels(&[
            ("lazymc.join.forward.address", "127.0.0.1:25565"),
            ("lazymc.join.forward.send_proxy_v2", "true"),
        ]));

        assert!(sections.is_empty());
    }

    /// Renders a config through the real serializer, in a scratch directory
    /// since `from_container_labels` writes the generated file to the cwd.
    fn render(extra: &[(&str, &str)]) -> String {
        use std::sync::Mutex;
        static CWD_LOCK: Mutex<()> = Mutex::new(());
        let _guard = CWD_LOCK.lock().unwrap_or_else(|err| err.into_inner());

        let dir = std::env::temp_dir().join(format!("ldp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        std::env::set_var("LAZYMC_VERSION", "0.2.11");
        std::env::set_var("LAZYMC_LEGACY_VERSION", "0.2.10");

        let mut pairs: Vec<(&str, &str)> = vec![
            ("lazymc.group", "mc"),
            ("lazymc.server.address", "127.0.0.1:25565"),
        ];
        pairs.extend_from_slice(extra);

        let toml = Config::from_container_labels(labels(&pairs)).as_toml_string();

        std::env::set_current_dir(previous).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        toml
    }

    #[test]
    fn forward_rules_render_as_an_array_of_tables() {
        let toml = render(&[
            ("lazymc.forward.geyser.server", "127.0.0.1:19132"),
            ("lazymc.forward.geyser.proto", "bedrock"),
        ]);

        assert!(toml.contains("[[forward]]"), "{}", toml);

        let parsed: toml::Table = toml.parse().unwrap();
        let forward = parsed["forward"].as_array().unwrap();
        assert_eq!(forward.len(), 1);
        assert_eq!(forward[0]["public"].as_str(), Some("0.0.0.0:19132"));
        assert_eq!(forward[0]["proto"].as_str(), Some("bedrock"));
    }

    /// A bare `forward = []` would be emitted after the section tables above it,
    /// which the TOML serializer rejects outright. Every existing user without
    /// forward rules runs through this path, so it must stay empty-skipped.
    #[test]
    fn a_config_without_forward_rules_still_renders() {
        let toml = render(&[]);

        assert!(!toml.contains("forward = []"), "{}", toml);
        toml.parse::<toml::Table>().unwrap();
    }
}
