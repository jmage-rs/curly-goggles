use sodiumoxide::crypto::secretbox;

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
}

const CONNECTION_TOKEN: mio::Token = mio::Token(0);

impl Oxy {
    fn new(connection: mio::net::TcpStream, config: Config) -> Oxy {
        let poll = mio::Poll::new().unwrap();
        Oxy {
            connection,
            config,
            poll,
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

    fn send_initial_message(&mut self) {
        let mut message = [0u8; 1024];
        let nonce = secretbox::gen_nonce().0;
        message[..nonce.len()].copy_from_slice(&nonce);
        use rand::Rng;
        let front_pad: usize = rand::thread_rng().gen_range(0, 100);
        let rear_pad: usize = rand::thread_rng().gen_range(0, 100);
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
