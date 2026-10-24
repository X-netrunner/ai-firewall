//---------------------------
// 6.1 `ai-firewall top`: live dashboard in the Halcyon palette
//---------------------------
//
// Reads /run/ai-firewall/status.json (written by the daemon every 3 s) and the
// wallpaper palette Halcyon's `hx palette` writes to ~/.cache/island/palette.json,
// re-reading both so the colours follow wallpaper changes while it's open.

use crate::net::unix_secs;
use crate::state;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Sparkline, Table, TableState};
use ratatui::{DefaultTerminal, Frame};
use serde::Deserialize;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const REFRESH: Duration = Duration::from_secs(1);
const HISTORY: usize = 120;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct StatusView {
    pub pid: u32,
    pub mode: String,
    pub interface: Option<String>,
    pub xdp_mode: Option<String>,
    pub udp_strict: bool,
    pub started_unix: u64,
    pub updated_unix: u64,
    pub attaches: u64,
    pub passed: u64,
    pub dropped_blocklist: u64,
    pub dropped_policy: u64,
    pub events_lost: u64,
    pub tracked_sources: usize,
    pub allow_tcp: Vec<u16>,
    pub allow_udp: Vec<u16>,
    pub bans: Vec<BanView>,
    pub recent: Vec<RecentView>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct BanView {
    pub ip: String,
    pub remaining_secs: u64,
    pub reason: String,
    pub source: String,
    pub strikes: u32,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct RecentView {
    pub ip: String,
    pub reason: String,
    pub ports: String,
    pub score: f32,
    pub secs: u64,
    pub strikes: u32,
    pub at_unix: u64,
    pub enforced: bool,
}

impl StatusView {
    pub fn read() -> Option<Self> {
        // AI_FIREWALL_STATUS lets the dashboard be previewed against a sample file
        let path = std::env::var("AI_FIREWALL_STATUS").unwrap_or_else(|_| state::STATUS_FILE.into());
        serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
    }

    pub fn alive(&self) -> bool {
        std::path::Path::new(&format!("/proc/{}", self.pid)).exists()
            && unix_secs().saturating_sub(self.updated_unix) < 30
    }
}

pub fn duration(secs: u64) -> String {
    match secs {
        0 => "forever".into(),
        s if s < 120 => format!("{s}s"),
        s if s < 7200 => format!("{}m", s / 60),
        s => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
    }
}

fn count(n: u64) -> String {
    match n {
        n if n >= 10_000_000 => format!("{:.0}M", n as f64 / 1e6),
        n if n >= 1_000_000 => format!("{:.1}M", n as f64 / 1e6),
        n if n >= 10_000 => format!("{:.0}k", n as f64 / 1e3),
        n => n.to_string(),
    }
}

/// Halcyon's palette, with its built-in dark defaults when there's no palette file
#[derive(Clone, Copy)]
struct Pal {
    bg: Color,
    surface: Color,
    surface_hi: Color,
    accent: Color,
    accent2: Color,
    text: Color,
    muted: Color,
    good: Color,
    bad: Color,
    warn: Color,
}

impl Pal {
    fn halcyon_default() -> Self {
        Self {
            bg: hex("#14161f").unwrap(),
            surface: hex("#1e2130").unwrap(),
            surface_hi: hex("#272b3d").unwrap(),
            accent: hex("#9aa9d4").unwrap(),
            accent2: hex("#c2add8").unwrap(),
            text: hex("#dcdde8").unwrap(),
            muted: hex("#9496a8").unwrap(),
            good: hex("#8fd6a8").unwrap(),
            bad: hex("#f2879b").unwrap(),
            warn: hex("#f0c27b").unwrap(),
        }
    }

    fn load(path: &Option<PathBuf>) -> Self {
        let mut pal = Self::halcyon_default();
        let Some(json) = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        else {
            return pal;
        };
        let get = |k: &str| json[k].as_str().and_then(hex);
        for (slot, key) in [
            (&mut pal.bg, "bg"),
            (&mut pal.surface, "surface"),
            (&mut pal.surface_hi, "surfaceHi"),
            (&mut pal.accent, "accent"),
            (&mut pal.accent2, "accent2"),
            (&mut pal.text, "text"),
            (&mut pal.muted, "muted"),
        ] {
            if let Some(c) = get(key) {
                *slot = c;
            }
        }
        pal
    }
}

fn hex(s: &str) -> Option<Color> {
    let s = s.strip_prefix('#')?;
    if s.len() != 6 {
        return None;
    }
    let v = u32::from_str_radix(s, 16).ok()?;
    Some(Color::Rgb((v >> 16) as u8, (v >> 8) as u8, v as u8))
}

/// The palette belongs to the desktop user, also when this runs under sudo
fn palette_path() -> Option<PathBuf> {
    let home = match std::env::var("SUDO_USER") {
        Ok(user) if unsafe { libc::geteuid() } == 0 => std::fs::read_to_string("/etc/passwd")
            .ok()?
            .lines()
            .map(|l| l.split(':').collect::<Vec<_>>())
            .find(|f| f.len() > 5 && f[0] == user)
            .map(|f| PathBuf::from(f[5]))?,
        _ => PathBuf::from(std::env::var_os("HOME")?),
    };
    Some(home.join(".cache/island/palette.json"))
}

enum Prompt {
    None,
    Ban(String),
}

struct App {
    status: Option<StatusView>,
    pal: Pal,
    pal_path: Option<PathBuf>,
    bans: TableState,
    drops: VecDeque<u64>,
    passes: VecDeque<u64>,
    last: Option<(u64, u64)>,
    prompt: Prompt,
    message: Option<(String, bool, Instant)>,
}

impl App {
    fn refresh(&mut self) {
        self.pal = Pal::load(&self.pal_path);
        self.status = StatusView::read();
        if let Some(s) = &self.status {
            let dropped = s.dropped_policy + s.dropped_blocklist;
            if let Some((p, d)) = self.last {
                push(&mut self.passes, s.passed.saturating_sub(p));
                push(&mut self.drops, dropped.saturating_sub(d));
            }
            self.last = Some((s.passed, dropped));
            let n = s.bans.len();
            match self.bans.selected() {
                _ if n == 0 => self.bans.select(None),
                None => self.bans.select(Some(0)),
                Some(i) if i >= n => self.bans.select(Some(n - 1)),
                _ => {}
            }
        }
    }

    fn say(&mut self, text: impl Into<String>, ok: bool) {
        self.message = Some((text.into(), ok, Instant::now()));
    }

    fn selected_ban(&self) -> Option<BanView> {
        let s = self.status.as_ref()?;
        s.bans.get(self.bans.selected()?).cloned()
    }
}

fn push(q: &mut VecDeque<u64>, v: u64) {
    if q.len() == HISTORY {
        q.pop_front();
    }
    q.push_back(v);
}

pub fn run() -> anyhow::Result<()> {
    if unsafe { libc::isatty(libc::STDOUT_FILENO) } != 1 {
        anyhow::bail!("the dashboard needs a terminal; use `ai-firewall status` in scripts");
    }
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut terminal);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal) -> anyhow::Result<()> {
    let pal_path = palette_path();
    let mut app = App {
        status: None,
        pal: Pal::load(&pal_path),
        pal_path,
        bans: TableState::default(),
        drops: VecDeque::new(),
        passes: VecDeque::new(),
        last: None,
        prompt: Prompt::None,
        message: None,
    };
    app.refresh();
    let mut next = Instant::now() + REFRESH;

    loop {
        terminal.draw(|f| draw(f, &mut app))?;
        let timeout = next.saturating_duration_since(Instant::now());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if let Prompt::Ban(input) = &mut app.prompt {
                    match key.code {
                        KeyCode::Esc => app.prompt = Prompt::None,
                        KeyCode::Backspace => {
                            input.pop();
                        }
                        KeyCode::Char(c) if c.is_ascii_hexdigit() || ".:/".contains(c) => input.push(c),
                        KeyCode::Enter => {
                            let text = std::mem::take(input);
                            app.prompt = Prompt::None;
                            match text.parse::<crate::addr::Src>() {
                                Ok(ip) => act(&mut app, &["ban", &ip.to_string(), "--minutes", "60"]),
                                Err(e) => app.say(e.to_string(), false),
                            }
                        }
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(()),
                    KeyCode::Down | KeyCode::Char('j') => app.bans.select_next(),
                    KeyCode::Up | KeyCode::Char('k') => app.bans.select_previous(),
                    KeyCode::Char('u') => match app.selected_ban() {
                        Some(b) if b.source == "config" => {
                            app.say(format!("{} is blocked in the config file; remove it there", b.ip), false)
                        }
                        Some(b) => act(&mut app, &["unban", &b.ip]),
                        None => app.say("no ban selected", false),
                    },
                    KeyCode::Char('b') => app.prompt = Prompt::Ban(String::new()),
                    KeyCode::Char('r') => act(&mut app, &["reload"]),
                    _ => {}
                }
            }
        } else {
            app.refresh();
            next = Instant::now() + REFRESH;
        }
    }
}

/// Changes go through the CLI (directly when root, else `sudo -n`) so there is one code path
fn act(app: &mut App, args: &[&str]) {
    let exe = std::env::current_exe().unwrap_or_else(|_| "ai-firewall".into());
    let output = if args[0] == "reload" {
        let mut c = std::process::Command::new(if unsafe { libc::geteuid() } == 0 { "systemctl" } else { "sudo" });
        if unsafe { libc::geteuid() } != 0 {
            c.args(["-n", "systemctl"]);
        }
        c.args(["reload", "ai-firewall"]).output()
    } else if unsafe { libc::geteuid() } == 0 {
        std::process::Command::new(&exe).args(args).output()
    } else {
        std::process::Command::new("sudo").arg("-n").arg(&exe).args(args).output()
    };
    match output {
        Ok(o) if o.status.success() => {
            let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
            app.say(if out.is_empty() { "config reloaded".into() } else { out }, true);
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains("password") {
                app.say("needs root: open the dashboard with `sudo ai-firewall top`", false);
            } else {
                app.say(err.trim().trim_start_matches("Error: ").to_string(), false);
            }
        }
        Err(e) => app.say(e.to_string(), false),
    }
}

fn pane<'a>(title: &'a str, pal: &Pal) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(pal.surface_hi))
        .title(Span::styled(format!(" {title} "), Style::default().fg(pal.accent).add_modifier(Modifier::BOLD)))
        .style(Style::default().bg(pal.surface).fg(pal.text))
}

fn draw(f: &mut Frame, app: &mut App) {
    let pal = app.pal;
    let area = f.area();
    f.render_widget(Block::default().style(Style::default().bg(pal.bg)), area);

    let [header, tiles, graph, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(4),
        Constraint::Length(6),
        Constraint::Min(6),
        Constraint::Length(1),
    ])
    .areas(area.inner(ratatui::layout::Margin { horizontal: 1, vertical: 0 }));

    let Some(s) = app.status.as_ref() else {
        draw_header(f, header, &pal, None);
        let msg = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled("ai-firewall is not running", Style::default().fg(pal.bad).add_modifier(Modifier::BOLD))),
            Line::from(Span::styled("start it with: sudo systemctl start ai-firewall", Style::default().fg(pal.muted))),
        ])
        .alignment(ratatui::layout::Alignment::Center)
        .block(pane("status", &pal));
        let [_, mid, _] = Layout::vertical([Constraint::Length(1), Constraint::Length(6), Constraint::Min(0)]).areas(body);
        f.render_widget(msg, mid);
        draw_footer(f, footer, app);
        return;
    };

    draw_header(f, header, &pal, Some(s));

    let tile_areas = Layout::horizontal([Constraint::Ratio(1, 4); 4]).spacing(1).split(tiles);
    let rate = |q: &VecDeque<u64>| q.back().copied().unwrap_or(0);
    let tiles_data = [
        ("passed", count(s.passed), format!("{}/s", rate(&app.passes)), pal.good),
        ("dropped by policy", count(s.dropped_policy), "closed ports".to_string(), pal.warn),
        ("from banned", count(s.dropped_blocklist), format!("{} banned", s.bans.len()), pal.bad),
        ("watching", s.tracked_sources.to_string(), format!("{} events lost", s.events_lost), pal.accent2),
    ];
    for (area, (label, value, sub, color)) in tile_areas.iter().zip(tiles_data) {
        let p = Paragraph::new(vec![
            Line::from(vec![
                Span::styled(value, Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::styled(format!("  {sub}"), Style::default().fg(pal.muted)),
            ]),
            Line::from(Span::styled(label, Style::default().fg(pal.muted))),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(pal.surface_hi))
                .style(Style::default().bg(pal.surface)),
        );
        f.render_widget(p, *area);
    }

    let drops: Vec<u64> = app.drops.iter().copied().collect();
    let width = graph.width.saturating_sub(2) as usize;
    let shown = &drops[drops.len().saturating_sub(width)..];
    let peak = shown.iter().copied().max().unwrap_or(0);
    let title = format!("drops per second, last {}  (peak {peak})", duration(shown.len().max(1) as u64));
    f.render_widget(
        Sparkline::default()
            .block(pane(&title, &pal))
            .data(shown)
            .style(Style::default().fg(pal.accent)),
        graph,
    );

    let [left, right] = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).spacing(1).areas(body);

    let rows: Vec<Row> = s
        .bans
        .iter()
        .map(|b| {
            let color = match b.source.as_str() {
                "auto" => pal.bad,
                "config" => pal.muted,
                _ => pal.warn,
            };
            Row::new(vec![
                Cell::from(b.ip.clone()).style(Style::default().fg(pal.text)),
                Cell::from(duration(b.remaining_secs)).style(Style::default().fg(pal.accent2)),
                Cell::from(b.source.clone()).style(Style::default().fg(color)),
                Cell::from(b.reason.clone()).style(Style::default().fg(pal.muted)),
            ])
        })
        .collect();
    let bans_title = format!("bans ({})", s.bans.len());
    let table = Table::new(rows, [Constraint::Length(24), Constraint::Length(8), Constraint::Length(6), Constraint::Min(10)])
        .header(Row::new(["address", "left", "by", "reason"]).style(Style::default().fg(pal.muted).add_modifier(Modifier::BOLD)))
        .row_highlight_style(Style::default().bg(pal.surface_hi).add_modifier(Modifier::BOLD))
        .highlight_symbol("▸ ")
        .column_spacing(1)
        .block(pane(&bans_title, &pal));
    if s.bans.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled("  nobody is banned", Style::default().fg(pal.muted))).block(pane(&bans_title, &pal)),
            left,
        );
    } else {
        f.render_stateful_widget(table, left, &mut app.bans);
    }

    let now = unix_secs();
    let mut lines: Vec<Line> = Vec::new();
    for r in s.recent.iter().rev() {
        lines.push(Line::from(vec![
            Span::styled(format!("{:>5} ", duration(now.saturating_sub(r.at_unix).max(1))), Style::default().fg(pal.muted)),
            Span::styled(format!("{:15} ", r.ip), Style::default().fg(pal.text)),
            Span::styled(
                if r.enforced { r.reason.clone() } else { format!("{} (monitor)", r.reason) },
                Style::default().fg(if r.enforced { pal.bad } else { pal.warn }),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!("      {} · score {:.1} · strike {} · {}", r.ports, r.score, r.strikes, duration(r.secs)),
            Style::default().fg(pal.muted),
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled("  all quiet", Style::default().fg(pal.muted))));
    }
    f.render_widget(Paragraph::new(lines).block(pane("detections", &pal)), right);

    draw_footer(f, footer, app);

    if let Prompt::Ban(input) = &app.prompt {
        let w = 52.min(area.width);
        let popup = Rect { x: area.x + (area.width - w) / 2, y: area.y + area.height / 2 - 2, width: w, height: 3 };
        f.render_widget(Clear, popup);
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(input.clone(), Style::default().fg(pal.text)),
                Span::styled("▏", Style::default().fg(pal.accent)),
            ]))
            .block(pane("ban for 60 min · enter / esc", &pal)),
            popup,
        );
    }
}

fn draw_header(f: &mut Frame, area: Rect, pal: &Pal, s: Option<&StatusView>) {
    let mut spans = vec![Span::styled(" ai-firewall ", Style::default().fg(pal.bg).bg(pal.accent).add_modifier(Modifier::BOLD))];
    if let Some(s) = s {
        let (state, color) = if !s.alive() {
            ("not responding", pal.bad)
        } else if s.mode == "enforce" {
            ("protecting", pal.good)
        } else {
            ("monitoring only", pal.warn)
        };
        spans.push(Span::styled(format!("  ● {state}"), Style::default().fg(color).add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(
            format!(
                "   {} · {} XDP · up {}",
                s.interface.as_deref().unwrap_or("no uplink"),
                s.xdp_mode.as_deref().unwrap_or("-"),
                duration(s.updated_unix.saturating_sub(s.started_unix).max(1)),
            ),
            Style::default().fg(pal.muted),
        ));
        if s.attaches > 1 {
            spans.push(Span::styled(format!(" · healed {}x", s.attaches - 1), Style::default().fg(pal.accent2)));
        }
    }
    let ports = s.map(|s| {
        let fmt = |v: &[u16]| if v.is_empty() { "none".to_string() } else { v.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" ") };
        Line::from(vec![
            Span::styled(" open tcp ", Style::default().fg(pal.muted)),
            Span::styled(fmt(&s.allow_tcp), Style::default().fg(pal.text)),
            Span::styled("   udp ", Style::default().fg(pal.muted)),
            Span::styled(fmt(&s.allow_udp), Style::default().fg(pal.text)),
            Span::styled(
                if s.udp_strict { "   replies tracked" } else { "   replies by port range" },
                Style::default().fg(pal.muted),
            ),
        ])
    });
    let mut lines = vec![Line::from(""), Line::from(spans)];
    if let Some(p) = ports {
        lines.push(p);
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let pal = &app.pal;
    if let Some((text, ok, at)) = &app.message {
        if at.elapsed() < Duration::from_secs(6) {
            f.render_widget(
                Paragraph::new(Span::styled(format!(" {text}"), Style::default().fg(if *ok { pal.good } else { pal.bad }))),
                area,
            );
            return;
        }
    }
    let key = |k: &'static str| Span::styled(k, Style::default().fg(pal.accent).add_modifier(Modifier::BOLD));
    let label = |l: &'static str| Span::styled(l, Style::default().fg(pal.muted));
    f.render_widget(
        Paragraph::new(Line::from(vec![
            key(" ↑↓"), label(" select  "),
            key("u"), label(" unban  "),
            key("b"), label(" ban  "),
            key("r"), label(" reload config  "),
            key("q"), label(" quit"),
        ])),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn renders_sample_status() {
        let now = unix_secs();
        let status = StatusView {
            pid: std::process::id(),
            mode: "enforce".into(),
            interface: Some("wlp3s0".into()),
            xdp_mode: Some("generic".into()),
            started_unix: now - 7300,
            updated_unix: now,
            attaches: 3,
            passed: 1_284_551,
            dropped_policy: 4210,
            dropped_blocklist: 38_112,
            tracked_sources: 7,
            allow_tcp: vec![22],
            allow_udp: vec![68, 546, 5353],
            bans: vec![
                BanView { ip: "45.33.32.156".into(), remaining_secs: 412, reason: "port scan".into(), source: "auto".into(), strikes: 2 },
                BanView { ip: "203.0.113.7".into(), remaining_secs: 0, reason: "blocked in config".into(), source: "config".into(), strikes: 0 },
            ],
            recent: vec![RecentView { ip: "45.33.32.156".into(), reason: "port scan".into(), ports: "tcp 21 22 23 80 +9".into(), score: 1.3, secs: 240, strikes: 2, at_unix: now - 95, enforced: true }],
            ..Default::default()
        };
        let mut app = App {
            status: Some(status),
            pal: Pal::halcyon_default(),
            pal_path: None,
            bans: TableState::default().with_selected(Some(0)),
            drops: (0..60).map(|i| (i * 7 % 23) as u64).collect(),
            passes: VecDeque::from([420]),
            last: None,
            prompt: Prompt::None,
            message: None,
        };
        let mut term = Terminal::new(TestBackend::new(100, 28)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let buf = term.backend().buffer();
        let text: String = (0..buf.area.height)
            .map(|y| (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect::<String>() + "\n")
            .collect();
        println!("{text}");
        assert!(text.contains("protecting"));
        assert!(text.contains("45.33.32.156"));
    }
}
