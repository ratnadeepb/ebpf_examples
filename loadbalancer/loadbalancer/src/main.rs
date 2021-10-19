use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use loadbalancer_common::PacketLog;
use std::{
    convert::{TryFrom, TryInto},
    env,
    fs,
    net,
    // sync::atomic::{AtomicBool, Ordering},
    // sync::Arc,
    // thread,
    // time::Duration,
};
use structopt::StructOpt;
use tokio::{signal, task};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let path = match env::args().nth(1) {
        Some(iface) => iface,
        None => panic!("not path provided"),
    };
    let iface = match env::args().nth(2) {
        Some(iface) => iface,
        None => "eth0".to_string(),
    };

    let data = fs::read(path)?;
    let mut bpf = Bpf::load(&data)?;

    let probe: &mut Xdp = bpf.program_mut("loadbalancer")?.try_into()?;
    probe.load()?;
    probe.attach(&iface, XdpFlags::default())?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = net::Ipv4Addr::from(data.src_addr);
                    let dst_addr = net::Ipv4Addr::from(data.dst_addr);
                    println!("LOG: SRC {} DST: {} ACTION {}", src_addr, dst_addr, data.action);
                }
            }
        });
    }

    // if let Err(e) = try_main() {
    //     eprintln!("error: {:#}", e);
    // }
    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    path: String,
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
}

// fn try_main() -> Result<(), anyhow::Error> {
//     let opt = Opt::from_args();
//     let mut bpf = Bpf::load_file(&opt.path)?;
//     let program: &mut Xdp = bpf.program_mut("loadbalancer")?.try_into()?;
//     program.load()?;
//     program.attach(&opt.iface, XdpFlags::default())?;

//     let running = Arc::new(AtomicBool::new(true));
//     let r = running.clone();

//     ctrlc::set_handler(move || {
//         r.store(false, Ordering::SeqCst);
//     })
//     .expect("Error setting Ctrl-C handler");

//     println!("Waiting for Ctrl-C...");
//     while running.load(Ordering::SeqCst) {
//         thread::sleep(Duration::from_millis(500))
//     }
//     println!("Exiting...");

//     Ok(())
// }
