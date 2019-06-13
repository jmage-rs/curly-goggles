#![allow(dead_code)]
#![allow(unused_variables)]

use sodiumoxide::crypto::pwhash::argon2id13;
use sodiumoxide::crypto::{box_, secretbox};

#[derive(structopt::StructOpt, Clone)]
struct Config {
    #[structopt(long = "mode")]
    mode: Mode,
    #[structopt(long = "password")]
    password: Option<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Server,
    Client,
}

enum TypeData {
    Server(ServerData),
    Client(ClientData),
}

#[derive(Default)]
struct ServerData {}

#[derive(Default)]
struct ClientData {}

impl TypeData {
    pub fn server(&self) -> &ServerData {
        match self {
            TypeData::Server(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }

    pub fn server_mut(&mut self) -> &mut ServerData {
        match self {
            TypeData::Server(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }

    pub fn client(&self) -> &ClientData {
        match self {
            TypeData::Client(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }

    pub fn client_mut(&mut self) -> &mut ClientData {
        match self {
            TypeData::Client(x) => x,
            _ => panic!("Wrong typedata type"),
        }
    }
}

impl std::str::FromStr for Mode {
    type Err = &'static str;
    fn from_str(src: &str) -> Result<Mode, &'static str> {
        match src {
            "server" => Ok(Mode::Server),
            "mode" => Ok(Mode::Client),
            _ => Err("invalid mode"),
        }
    }
}

struct Oxy {
    connection: mio::net::TcpStream,
    config: Config,
    poll: mio::Poll,
    key: Option<secretbox::Key>,
    typedata: TypeData,
}

const CONNECTION_TOKEN: mio::Token = mio::Token(0);

impl Oxy {
    fn new(connection: mio::net::TcpStream, config: Config) -> Oxy {
        let poll = mio::Poll::new().unwrap();
        let typedata = match &config.mode {
            Mode::Server => TypeData::Server(ServerData::default()),
            Mode::Client => TypeData::Client(ClientData::default()),
        };
        Oxy {
            connection,
            config,
            poll,
            key: None,
            typedata,
        }
    }

    fn init(&mut self) {
        sodiumoxide::init().unwrap();
        self.poll
            .register(
                &self.connection,
                CONNECTION_TOKEN,
                mio::Ready::readable(),
                mio::PollOpt::edge(),
            )
            .unwrap();
        if self.config.mode == Mode::Client {
            self.send_initial_message();
        }
    }

    fn seed_from_password(&self) -> box_::Seed {
        let salt =
            argon2id13::Salt::from_slice(b"i7'\xe0\xf0\xe6\xc0\xb2\xf9V\x1b\xe4\xc8\xb6\x95\x07")
                .unwrap();
        let mut key_buffer = [0u8; 32];
        argon2id13::derive_key(
            &mut key_buffer[..],
            self.config
                .password
                .as_ref()
                .map(|x| x.as_bytes())
                .unwrap_or(b""),
            &salt,
            argon2id13::OPSLIMIT_INTERACTIVE,
            argon2id13::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        box_::Seed(key_buffer)
    }

    fn send_initial_message(&mut self) {
        use rand::Rng;
        let mut message = [0u8; 1024];
        let mut encrypted_message = [0u8; 32 + 24 + 24 + 16];
        let front_pad: usize = rand::thread_rng().gen_range(0, 100);
        let nonce = box_::gen_nonce();
        let (pk, sk) = box_::gen_keypair();
        let session_key = secretbox::gen_key().0;
        let client_to_server_nonce = secretbox::gen_nonce().0;
        let server_to_client_nonce = secretbox::gen_nonce().0;
        let seed = self.seed_from_password();
        let server_pk = box_::keypair_from_seed(&seed).0;

        {
            // Fill encrypted_message with plaintext
            let (session_key_zone, tail) = encrypted_message.split_at_mut(session_key.len());
            let (client_to_server_nonce_zone, tail) =
                tail.split_at_mut(client_to_server_nonce.len());
            let (server_to_client_nonce_zone, _tag_zone) =
                tail.split_at_mut(server_to_client_nonce.len());

            session_key_zone.copy_from_slice(&session_key[..]);
            client_to_server_nonce_zone.copy_from_slice(&client_to_server_nonce[..]);
            server_to_client_nonce_zone.copy_from_slice(&server_to_client_nonce[..]);
        }

        {
            // Encrypt encrypted_message
            let tag = box_::seal_detached(&mut encrypted_message, &nonce, &server_pk, &sk);
            let tag_start = encrypted_message.len() - 16;
            encrypted_message[tag_start..].copy_from_slice(&tag.0[..]);
        }

        let (outer_nonce, tail) = message.split_at_mut(nonce.0.len());
        let (ephemeral_pk, tail) = tail.split_at_mut(pk.0.len());
        let (padding, tail) = tail.split_at_mut(front_pad);
        let (encrypted_zone, tail) = tail.split_at_mut(encrypted_message.len());

        outer_nonce.copy_from_slice(&nonce.0);
        ephemeral_pk.copy_from_slice(&pk.0[..]);
        sodiumoxide::randombytes::randombytes_into(padding);
        encrypted_zone.copy_from_slice(&encrypted_message);
        sodiumoxide::randombytes::randombytes_into(tail);
    }

    fn dispatch_event(&mut self, event: &mio::Event) {
        ();
    }

    fn reregister(&mut self) {
        ();
    }

    fn run(&mut self) {
        self.init();
        let mut events = mio::Events::with_capacity(1024);
        loop {
            self.reregister();
            self.poll.poll(&mut events, None).unwrap();
            for event in &events {
                self.dispatch_event(&event);
            }
            events.clear();
        }
    }
}

fn main() {
    let config = <Config as structopt::StructOpt>::from_args();
    match config.mode {
        Mode::Server => loop {
            let bind = std::net::TcpListener::bind("127.0.0.1:2600").unwrap();
            let (connection, _) = bind.accept().unwrap();
            let connection = mio::net::TcpStream::from_stream(connection).unwrap();
            let config2 = config.clone();
            std::thread::spawn(move || {
                let mut oxy = Oxy::new(connection, config2);
                oxy.run();
            });
        },
        Mode::Client => {
            let connection = std::net::TcpStream::connect("127.0.0.1:2600").unwrap();
            let connection = mio::net::TcpStream::from_stream(connection).unwrap();
            let mut oxy = Oxy::new(connection, config);
            oxy.run();
        }
    }
}
