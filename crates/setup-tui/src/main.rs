//! currawong-setup: terminal wizard that writes the Currawong config, checks
//! it with `currawongd --check-config` and starts the gateway.
//! `--firstboot` (the appliance) also sets the hostname and root password.
use clap::Parser;
use currawong_setup::{
    apply,
    form::{Action, Form, Key, Kind},
};
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph, Wrap},
    DefaultTerminal, Frame, TerminalOptions, Viewport,
};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

const TITLE: &str = " Currawong setup ";
/// Consoles the appliance runs the wizard on. See currawong-firstboot@.service.
const FIRSTBOOT_TTYS: [&str; 2] = ["tty1", "ttyS0"];

#[derive(Parser)]
#[command(name = "currawong-setup")]
struct Args {
    /// Appliance first boot: also set the hostname and root password.
    #[arg(long)]
    firstboot: bool,
    #[arg(long, default_value = "/etc/currawong")]
    config_dir: PathBuf,
    #[arg(long, default_value = "/usr/bin/currawongd")]
    currawongd: PathBuf,
    /// Written when setup completes; the first-boot unit checks for it.
    #[arg(long, default_value = "/var/lib/currawong/.setup-complete")]
    marker: PathBuf,
    #[arg(long, default_value = "/etc/group")]
    group_file: PathBuf,
    #[arg(long, default_value = "/run/currawong-setup.lock")]
    lock: PathBuf,
    /// Console this first-boot instance runs on, e.g. ttyS0. When setup is
    /// done, the instances on the other consoles are stopped.
    #[arg(long)]
    tty: Option<String>,
}

enum Outcome {
    Done(String),
    Quit,
}

fn main() {
    let args = Args::parse();
    let form = Form::new(
        args.firstboot,
        &default_hostname(),
        apply::cert_exists(&args.config_dir),
    );
    let mut terminal = init_terminal();
    let outcome = run(&mut terminal, form, &args);
    if let Ok(Outcome::Done(summary)) = &outcome {
        let _ = show_message(&mut terminal, summary);
        let _ = wait_for_key();
    }
    ratatui::restore();
    match outcome {
        Ok(Outcome::Done(_)) => {}
        Ok(Outcome::Quit) => {
            eprintln!("currawong-setup: cancelled before setup completed");
            std::process::exit(1);
        }
        Err(err) => {
            eprintln!("currawong-setup: {err}");
            std::process::exit(1);
        }
    }
}

/// A serial console reports a 0x0 window, so fall back to 80x24.
fn init_terminal() -> DefaultTerminal {
    let viewport = match ratatui::crossterm::terminal::size() {
        Ok((cols, rows)) if cols > 0 && rows > 0 => Viewport::Fullscreen,
        _ => Viewport::Fixed(Rect::new(0, 0, 80, 24)),
    };
    ratatui::init_with_options(TerminalOptions { viewport })
}

fn default_hostname() -> String {
    Command::new("hostname")
        .arg("-f")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default()
}

fn run(terminal: &mut DefaultTerminal, mut form: Form, args: &Args) -> Result<Outcome, String> {
    loop {
        terminal
            .draw(|frame| draw_form(frame, &form))
            .map_err(|err| err.to_string())?;
        let Some(key) = read_key()? else { continue };
        match form.handle(key) {
            Action::None => {}
            // The appliance console stays on the wizard until setup is done.
            Action::Quit if args.firstboot => {
                form.error = Some("Setup must be completed before this console can log in.".into())
            }
            Action::Quit => return Ok(Outcome::Quit),
            Action::Submit => {
                let Some((answers, password)) = form.validate() else {
                    continue;
                };
                show_message(terminal, "Saving and starting currawongd...")?;
                match save(args, &answers, form.new_cert(), password.as_deref()) {
                    Ok(summary) => return Ok(Outcome::Done(summary)),
                    Err(err) => form.error = Some(err),
                }
                blank(terminal)?;
            }
        }
    }
}

fn read_key() -> Result<Option<Key>, String> {
    let Event::Key(key) = event::read().map_err(|err| err.to_string())? else {
        return Ok(None);
    };
    if key.kind != KeyEventKind::Press {
        return Ok(None);
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        // Serial terminals may send LF (Ctrl-J) for Enter. Other control
        // chords are ignored rather than typed as letters.
        return Ok(match key.code {
            KeyCode::Char('c') => Some(Key::Esc),
            KeyCode::Char('j') | KeyCode::Char('m') => Some(Key::Enter),
            _ => None,
        });
    }
    Ok(match key.code {
        KeyCode::Char(ch) => Some(Key::Char(ch)),
        KeyCode::Backspace => Some(Key::Backspace),
        KeyCode::Enter => Some(Key::Enter),
        KeyCode::Tab => Some(Key::Tab),
        KeyCode::BackTab => Some(Key::BackTab),
        KeyCode::Up => Some(Key::Up),
        KeyCode::Down => Some(Key::Down),
        KeyCode::Esc => Some(Key::Esc),
        _ => None,
    })
}

fn wait_for_key() -> Result<(), String> {
    while read_key()?.is_none() {}
    Ok(())
}

/// Write everything, in an order where a failure leaves a working system:
/// the config is checked before it replaces the old one.
fn save(
    args: &Args,
    answers: &currawong_setup::answers::Answers,
    new_cert: bool,
    root_password: Option<&str>,
) -> Result<String, String> {
    // The appliance shows the wizard on more than one console.
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&args.lock)
        .ok();
    if let Some(lock) = &lock {
        if lock.try_lock().is_err() {
            return Err("setup is being saved on another console".into());
        }
    }
    if args.firstboot && args.marker.exists() {
        return Err("setup was already completed on another console".into());
    }
    let gid = apply::group_id(&args.group_file, "currawong");
    let config =
        apply::install_config(&args.config_dir, &answers.to_toml(), gid, &args.currawongd)?;
    if new_cert {
        apply::write_self_signed(&args.config_dir, &answers.hostname, gid)?;
    }
    if let Some(password) = root_password {
        run_cmd("hostnamectl", &["set-hostname", &answers.hostname])?;
        set_root_password(password)?;
    }
    if answers.clamd {
        // Best effort: freshclam fetches signatures; until then mail is deferred.
        let _ = run_cmd(
            "systemctl",
            &[
                "enable",
                "--now",
                "clamav-freshclam.service",
                "clamav-daemon.service",
            ],
        );
    }
    run_cmd("systemctl", &["enable", "currawongd.service"])?;
    run_cmd("systemctl", &["restart", "currawongd.service"])?;
    if let Some(dir) = args.marker.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    File::create(&args.marker).map_err(|err| format!("{}: {err}", args.marker.display()))?;
    if args.firstboot {
        stop_other_consoles(args.tty.as_deref().unwrap_or_default());
    }
    Ok(format!(
        "Currawong is running.\n\n\
         SMTP: 25 inbound, 587 and 465 submission\n\
         Health: curl http://127.0.0.1:9090/healthz\n\
         Config: {}\n\n\
         Replace {}/cert.pem and key.pem with a CA-issued certificate, then run\n\
         systemctl reload currawongd\n\n\
         Press any key.",
        config.display(),
        args.config_dir.display()
    ))
}

fn run_cmd(program: &str, cmd_args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(cmd_args)
        .output()
        .map_err(|err| format!("{program}: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {}: {}",
            cmd_args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Through chpasswd's stdin, so the password is never in argv or a file.
fn set_root_password(password: &str) -> Result<(), String> {
    let mut child = Command::new("chpasswd")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("chpasswd: {err}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("root:{password}\n").as_bytes())
            .map_err(|err| format!("chpasswd: {err}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| format!("chpasswd: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "chpasswd: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Setup is done; release the other consoles to their login prompts.
fn stop_other_consoles(mine: &str) {
    for tty in FIRSTBOOT_TTYS.iter().filter(|tty| **tty != mine) {
        let unit = format!("currawong-firstboot@{tty}.service");
        let _ = run_cmd("systemctl", &["--no-block", "stop", &unit]);
    }
}

fn draw_form(frame: &mut Frame, form: &Form) {
    let focused = Style::new().add_modifier(Modifier::REVERSED);
    let mut lines = vec![
        Line::from("Mail content stays on this host. Australian residency mode is on."),
        Line::from("Tab or arrows move, Space toggles, Enter on Save writes the config."),
        Line::from(""),
    ];
    for (index, field) in form.fields.iter().enumerate() {
        let shown = match field.kind {
            Kind::Text => field.value.clone(),
            Kind::Secret => "*".repeat(field.value.chars().count()),
            Kind::Toggle => if field.on { "[x]" } else { "[ ]" }.to_string(),
        };
        let style = if form.focus == index {
            focused
        } else {
            Style::new()
        };
        lines.push(Line::from(vec![
            Span::raw(format!("{:>17}  ", field.label)),
            Span::styled(format!("{shown} "), style),
        ]));
    }
    lines.push(Line::from(""));
    let save_style = if form.on_save() {
        focused
    } else {
        Style::new()
    };
    lines.push(Line::from(vec![
        Span::raw(" ".repeat(19)),
        Span::styled("[ Save ]", save_style),
    ]));
    lines.push(Line::from(""));
    if let Some(field) = form.fields.get(form.focus) {
        lines.push(Line::from(field.help));
    }
    if let Some(err) = &form.error {
        lines.push(Line::styled(err.clone(), Style::new().fg(Color::Red)));
    }
    render(frame, lines);
}

/// ratatui only redraws changed cells. Drawing a blank frame first makes the
/// next screen write all of its text, so it reads cleanly in a serial log.
/// (`Terminal::clear` asks for the cursor position, which a serial console
/// never answers.)
fn blank(terminal: &mut DefaultTerminal) -> Result<(), String> {
    terminal
        .draw(|_| {})
        .map(|_| ())
        .map_err(|err| err.to_string())
}

fn show_message(terminal: &mut DefaultTerminal, text: &str) -> Result<(), String> {
    blank(terminal)?;
    terminal
        .draw(|frame| draw_message(frame, text))
        .map(|_| ())
        .map_err(|err| err.to_string())
}

fn draw_message(frame: &mut Frame, text: &str) {
    render(frame, text.lines().map(Line::from).collect());
}

fn render(frame: &mut Frame, lines: Vec<Line>) {
    let block = Block::bordered().title(TITLE);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        frame.area(),
    );
}
