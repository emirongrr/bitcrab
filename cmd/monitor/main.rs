use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table},
    Frame, Terminal,
};
use serde_json::Value;
use std::{
    io,
    time::{Duration, Instant},
};

struct App {
    rpc_url: String,
    blockchain_info: Option<Value>,
    network_info: Option<Value>,
    peers: Vec<Value>,
    last_update: String,
}

impl App {
    fn new(rpc_url: String) -> App {
        App {
            rpc_url,
            blockchain_info: None,
            network_info: None,
            peers: Vec::new(),
            last_update: "Never".to_string(),
        }
    }

    async fn update(&mut self) -> eyre::Result<()> {
        let client = reqwest::Client::new();

        // 1. Fetch blockchain info
        let bc_res = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "1.0",
                "id": "monitor",
                "method": "getblockchaininfo",
                "params": []
            }))
            .send()
            .await?
            .json::<Value>()
            .await?;

        if let Some(res) = bc_res.get("result") {
            self.blockchain_info = Some(res.clone());
        }

        // 2. Fetch network info
        let net_res = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "1.0",
                "id": "monitor",
                "method": "getnetworkinfo",
                "params": []
            }))
            .send()
            .await?
            .json::<Value>()
            .await?;

        if let Some(res) = net_res.get("result") {
            self.network_info = Some(res.clone());
        }

        // 3. Fetch peers
        let peer_res = client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "1.0",
                "id": "monitor",
                "method": "getpeerinfo",
                "params": []
            }))
            .send()
            .await?
            .json::<Value>()
            .await?;

        if let Some(res) = peer_res.get("result") {
            if let Some(list) = res.as_array() {
                self.peers = list.clone();
            }
        }

        self.last_update = chrono::Local::now().format("%H:%M:%S").to_string();
        Ok(())
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run loop
    let mut app = App::new("http://127.0.0.1:8332".to_string());
    let res = run_app(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}

async fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(1000);

    // Initial update
    let _ = app.update().await;

    loop {
        terminal.draw(|f| ui(f, app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    return Ok(());
                }
                if let KeyCode::Char('r') = key.code {
                    let _ = app.update().await;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            let _ = app.update().await;
            last_tick = Instant::now();
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Length(10),
                Constraint::Min(5),
            ]
            .as_ref(),
        )
        .split(f.size());

    // 1. Header
    let subver = app
        .network_info
        .as_ref()
        .and_then(|i| i.get("subversion"))
        .and_then(|v| v.as_str())
        .unwrap_or("bitcrab");

    let header = Paragraph::new(format!(
        " Bitcrab Node Monitor | Version: {} | Last Update: {} | Press 'q' to quit",
        subver, app.last_update
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(header, chunks[0]);

    // 2. Stats
    let height = app
        .blockchain_info
        .as_ref()
        .and_then(|i| i.get("blocks"))
        .map(|v| v.to_string())
        .unwrap_or_else(|| "0".to_string());

    let best_hash = app
        .blockchain_info
        .as_ref()
        .and_then(|i| i.get("bestblockhash"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let network = app
        .blockchain_info
        .as_ref()
        .and_then(|i| i.get("chain"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let conn_count = app.peers.len();

    let stats_text = vec![
        format!(" Network    : {}", network),
        format!(" Height     : {}", height),
        format!(" Connections: {}", conn_count),
        format!(" Best Block : {}", best_hash),
    ];

    let stats_list: Vec<ListItem> = stats_text
        .iter()
        .map(|s| ListItem::new(s.as_str()))
        .collect();

    let stats =
        List::new(stats_list).block(Block::default().title(" Node Info ").borders(Borders::ALL));
    f.render_widget(stats, chunks[1]);

    // 3. Peers
    let rows: Vec<Row> = app
        .peers
        .iter()
        .map(|p| {
            let conntime = p.get("conntime").and_then(|v| v.as_u64()).unwrap_or(0);
            let conntime_fmt = if conntime > 3600 {
                format!("{}h {}m", conntime / 3600, (conntime % 3600) / 60)
            } else if conntime > 60 {
                format!("{}m {}s", conntime / 60, conntime % 60)
            } else {
                format!("{}s", conntime)
            };

            Row::new(vec![
                p.get("addr")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                p.get("subver")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                p.get("startingheight")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                conntime_fmt,
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(35),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ],
    )
    .header(
        Row::new(vec!["Address", "User Agent", "Height", "Uptime"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .title(" Connected Peers ")
            .borders(Borders::ALL),
    );

    f.render_widget(table, chunks[2]);
}
