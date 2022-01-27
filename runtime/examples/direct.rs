use futures::FutureExt;
use std::path::{Path, PathBuf};
use std::{
    env,
    io::{self, prelude::*},
    process::Stdio,
    sync::Arc,
};
use tokio::{
    process::{Child, Command},
    sync,
};
use ya_runtime_vm::guest_agent_comm::{GuestAgent, Notification, RedirectFdType};
use ya_runtime_vm::guest_agent_9p::{GuestAgent9p, Notification9p};

struct Notifications {
    process_died: sync::Notify,
    output_available: sync::Notify,
}
struct Notifications9p {
    process_died: sync::Notify,
    output_available: sync::Notify,
}
use futures::lock::Mutex;
use tokio::time::{delay_for, Duration};

impl Notifications {
    fn new() -> Self {
        Notifications {
            process_died: sync::Notify::new(),
            output_available: sync::Notify::new(),
        }
    }

    fn handle(&self, notification: Notification) {
        match notification {
            Notification::OutputAvailable { id, fd } => {
                log::debug!("Process {} has output available on fd {}", id, fd);
                self.output_available.notify();
            }
            Notification::ProcessDied { id, reason } => {
                log::debug!("Process {} died with {:?}", id, reason);
                self.process_died.notify();
            }
        }
    }
}

impl Notifications9p {
    fn new() -> Self {
        Notifications9p {
            process_died: sync::Notify::new(),
            output_available: sync::Notify::new(),
        }
    }

    fn handle(&self, notification: Notification9p) {
        match notification {
            Notification9p::OutputAvailable { id, fd } => {
                log::debug!("Process {} has output available on fd {}", id, fd);
                self.output_available.notify();
            }
            Notification9p::ProcessDied { id, reason } => {
                log::debug!("Process {} died with {:?}", id, reason);
                self.process_died.notify();
            }
        }
    }
}

async fn run_process_with_output(
    ga: &mut GuestAgent,
    notifications: &Notifications,
    bin: &str,
    argv: &[&str],
) -> io::Result<()> {
    let id = ga
        .run_process(
            bin,
            argv,
            None,
            0,
            0,
            &[
                None,
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
                Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
            ],
            None,
        )
        .await?
        .expect("Run process failed");
    println!("Spawned process with id: {}", id);
    notifications.process_died.notified().await;
    notifications.output_available.notified().await;
    match ga.query_output(id, 1, 0, u64::MAX).await? {
        Ok(out) => {
            println!("Output:");
            io::stdout().write_all(&out)?;
        }
        Err(code) => println!("Output query failed with: {}", code),
    }
    Ok(())
}

fn get_project_dir() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .canonicalize()
        .expect("invalid manifest dir")
}

fn get_root_dir() -> PathBuf {
    get_project_dir().parent().unwrap().to_owned()
}

fn join_as_string<P: AsRef<Path>>(path: P, file: impl ToString) -> String {
    path.as_ref()
        .join(file.to_string())
        .canonicalize()
        .unwrap()
        .display()
        .to_string()
}

fn spawn_vm<'a, P: AsRef<Path>>(temp_path: P, mount_args: &'a [(&'a str, impl ToString)]) -> Child {
    let root_dir = get_root_dir();
    let project_dir = get_project_dir();
    let runtime_dir = project_dir.join("poc").join("runtime");
    let init_dir = project_dir.join("init-container");

    let mut cmd = Command::new("vmrt");
    cmd.current_dir(runtime_dir).args(&[
        "-m",
        "256m",
        "-nographic",
        "-vga",
        "none",
        "-kernel",
        join_as_string(&init_dir, "vmlinuz-virt").as_str(),
        "-initrd",
        join_as_string(&init_dir, "initramfs.cpio.gz").as_str(),
        "-no-reboot",
        "-net",
        "none",
        "-enable-kvm",
        "-cpu",
        "host",
        "-smp",
        "1",
        "-append",
        "console=ttyS0 panic=1",
        "-device",
        "virtio-serial",
        "-device",
        "virtio-rng-pci",
        "-chardev",
        format!(
            "socket,path={},server,nowait,id=manager_cdev",
            temp_path.as_ref().join("manager.sock").display()
        )
        .as_str(),
        "-device",
        "virtserialport,chardev=manager_cdev,name=manager_port",
        "-drive",
        format!(
            "file={},cache=none,readonly=on,format=raw,if=virtio",
            root_dir.join("squashfs_drive").display()
        )
        .as_str(),
    ]);
    for (tag, path) in mount_args.iter() {
        cmd.args(&[
            "-virtfs",
            &format!(
                "local,id={tag},path={path},security_model=none,mount_tag={tag}",
                tag = tag,
                path = path.to_string()
            ),
        ]);
    }
    cmd.stdin(Stdio::null());
    cmd.spawn().expect("failed to spawn VM")
}

async fn simple_run_command(ga_mutex: &Arc<Mutex<GuestAgent>>, bin: &str, argv: &[&str], dir: &str, notifications: Option<&Arc<Notifications>>) -> io::Result<()> {
    let mut ga = ga_mutex.lock().await;

    io::stdout().write_all(std::format!("Command started: {0}\n", argv.join(" ")).as_str().as_bytes())?;

    let id = ga
        .run_process(
            bin,
            argv,
            None,
            0,
            0,
            &[
                None,
                Some(RedirectFdType::RedirectFdPipeBlocking(0x100000)),
                None,
            ],
            Some(dir),
        )
        .await?
        .expect("Run process failed");
    //println!("Spawned process with id: {}", id);
    if let Some(notifications) = notifications {
        notifications.process_died.notified().await;
    }
    let out = ga
        .query_output(id, 1, 0, u64::MAX)
        .await?
        .expect("Output query failed");
    //println!("Output:");
    io::stdout().write_all(&out)?;

    io::stdout().write_all(std::format!("Command finished: {0}\n", argv.join(" ")).as_str().as_bytes())?;

    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let temp_dir = tempdir::TempDir::new("ya-vm-direct").expect("Failed to create temp dir");
    let temp_path = temp_dir.path();
    let inner_path = temp_path.join("inner");

    std::fs::create_dir_all(&inner_path).expect("Failed to create a dir inside temp dir");
    let notifications = Arc::new(Notifications::new());
    let notifications2 = Arc::new(Notifications9p::new());

    log::info!("Temp path: {:?}", temp_path);
    let mount_args = [
        ("tag0", temp_path.display()),
        ("tag1", inner_path.display()),
    ];
    let should_spawn_vm = false;
    if should_spawn_vm {


        let _child = spawn_vm(&temp_path, &mount_args);
    }

    let ns = notifications.clone();
    let ns2 = notifications2.clone();
    /*
        #[cfg(windows)]
        let socket_address : SocketAddr = "127.0.0.1:9003".parse().unwrap();
        #[cfg(unix)]
        let socket_address = temp_path.join("manager.sock");
    */
    let ga_mutex = GuestAgent::connected("127.0.0.1:9003", 10, move |n, _g| {
        let notifications = ns.clone();
        async move { notifications.clone().handle(n) }.boxed()
    })
    .await?;

    /*
    let ga_mutex2 = GuestAgent9p::connected("127.0.0.1:9005", 10, move |n, _g| {
        let notifications2 = ns2.clone();
        async move { notifications2.clone().handle(n) }.boxed()
    }).await?;*/



    let mut ga = ga_mutex.lock().await;

    for (i, (tag, _)) in mount_args.iter().enumerate() {
        ga.mount(tag, &format!("/mnt/mnt{}/{}", i, tag))
            .await?
            .expect("Mount failed");
    }

    let no_redir = [None, None, None];

    delay_for(Duration::from_millis(1000)).await;
    simple_run_command(&ga_mutex, "/bin/ls", &["ls", "-la"], "/dev", Some(&notifications)).await?;
    delay_for(Duration::from_millis(1000)).await;
    simple_run_command(&ga_mutex, "/bin/bash", &["bash", "-c",  "mkdir host_files  > /result.log 2> /error.log; echo output:; cat /result.log; echo errors:;cat /error.log"], "/mnt", Some(&notifications)).await?;
    delay_for(Duration::from_millis(1000)).await;
    //simple_run_command(&ga_mutex, "/bin/bash", &["bash", "-c",  "echo DUPA >> /dev/vport0p3"], "/dev", Some(&notifications)).await?;

    simple_run_command(&ga_mutex, "/bin/bash", &["bash", "-c",  "mount -t 9p -o trans=fd,rfdno=/dev/vport0p3,wfdno=/dev/vport0p3,version=9p2000.L hostshare /mnt/host_files > /result.log 2> /error.log; echo output:; cat /result.log; echo errors:;cat /error.log"], "/dev", Some(&notifications)).await?;
    delay_for(Duration::from_millis(1000)).await;

    if false {
        let mut ga = ga_mutex.lock().await;


        //run_ls(&ga_mutex, &notifications, "/").await?;
        //run_ls(&ga_mutex, &notifications, "/bin").await?;
        //run_ls(&ga_mutex, &notifications, "/dev").await?;
        //run_ls(&ga_mutex, &notifications, "/mnt").await?;
        //run_cat(&ga_mutex, &notifications, "/dev", ".env").await?;




        run_process_with_output(
            &mut ga,
            &notifications,
            "/bin/ls",
            &["ls", "-al", "/mnt/mnt1/tag1"],
        )
        .await?;

        let fds = [
            None,
            Some(RedirectFdType::RedirectFdFile("/write_test".as_bytes())),
            None,
        ];
        let mut ga = ga_mutex.lock().await;

        let id = ga
            .run_process("/bin/echo", &["echo", "WRITE TEST"], None, 0, 0, &fds, None)
            .await?
            .expect("Run process failed");
        println!("Spawned process with id: {}", id);
        notifications.process_died.notified().await;

        run_process_with_output(
            &mut ga,
            &notifications,
            "/bin/cat",
            &["cat", "/mnt/mnt1/tag1/write_test"],
        )
        .await?;

        let id = ga
            .run_process("/bin/sleep", &["sleep", "10"], None, 0, 0, &no_redir, None)
            .await?
            .expect("Run process failed");
        println!("Spawned process with id: {}", id);

        ga.kill(id).await?.expect("Kill failed");
        notifications.process_died.notified().await;

        let id = ga
            .run_process(
                "/bin/bash",
                &[
                    "bash",
                    "-c",
                    "for i in {1..30}; do echo -ne a >> /big; sleep 1; done; cat /big",
                ],
                None,
                0,
                0,
                &[
                    None,
                    Some(RedirectFdType::RedirectFdPipeBlocking(0x1000)),
                    None,
                ],
                None,
            )
            .await?
            .expect("Run process failed");
        println!("Spawned process with id: {}", id);
        notifications.output_available.notified().await;
        let out = ga
            .query_output(id, 1, 0, u64::MAX)
            .await?
            .expect("Output query failed");
        println!(
            "Big output 1: {} {}",
            out.len(),
            out.iter().filter(|x| **x != 0x61).count()
        );
        notifications.output_available.notified().await;
        ga.quit().await?.expect("Quit failed");
        let out = ga
            .query_output(id, 1, 0, u64::MAX)
            .await?
            .expect("Output query failed");
        println!(
            "Big output 2: {} {}",
            out.len(),
            out.iter().filter(|x| **x != 0x61).count()
        );

        let id = ga
            .run_process(
                "/bin/bash",
                &[
                    "bash",
                    "-c",
                    "echo > /big; for i in {1..4000}; do echo -ne a >> /big; done; for i in {1..4096}; do echo -ne b >> /big; done; cat /big",
                ],
                None,
                0,
                0,
                &[
                    None,
                    Some(RedirectFdType::RedirectFdPipeCyclic(0x1000)),
                    None,
                ],
                None,
            )
            .await?
            .expect("Run process failed");
        println!("Spawned process with id: {}", id);
        notifications.process_died.notified().await;
        notifications.output_available.notified().await;
        let out = ga
            .query_output(id, 1, 0, u64::MAX)
            .await?
            .expect("Output query failed");
        println!(
            "Big output 1: {} {}",
            out.len(),
            out.iter().filter(|x| **x != 0x62).count()
        );

        let out = ga
            .query_output(id, 1, 0, u64::MAX)
            .await?
            .expect("Output query failed");
        println!("Big output 2: {}, expected 0", out.len());

        let id = ga
            .run_entrypoint("/bin/sleep", &["sleep", "2"], None, 0, 0, &no_redir, None)
            .await?
            .expect("Run process failed");
        println!("Spawned process with id: {}", id);
        notifications.process_died.notified().await;

        /* VM should quit now. */
        //let e = child.await.expect("failed to wait on child");
        //println!("{:?}", e);
    }
    Ok(())
}
