import React, { useMemo, useState } from 'react';
import {
  Activity,
  Bot,
  Database,
  Lock,
  LogOut,
  Network,
  Play,
  Radar,
  ScanLine,
  Server,
  Shield,
  ShieldAlert,
  Terminal,
  User,
  Zap
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';

const mockEvents = [
  {
    id: 'evt-1001',
    timestamp: '14:03:22',
    attack_type: 'Port Scan',
    src_ip: '192.168.2.10',
    dest_ip: '192.168.2.100',
    dest_port: '22-8080',
    signature_id: '100001',
    signature: 'LAB Port scan detected',
    action: 'BLOCKED'
  },
  {
    id: 'evt-1002',
    timestamp: '14:01:48',
    attack_type: 'SQL Injection',
    src_ip: '192.168.2.10',
    dest_ip: '192.168.2.100',
    dest_port: '80',
    signature_id: '100003',
    signature: 'LAB SQL Injection detected',
    action: 'ALERT'
  },
  {
    id: 'evt-1003',
    timestamp: '13:58:09',
    attack_type: 'Brute Force',
    src_ip: '192.168.2.10',
    dest_ip: '192.168.2.100',
    dest_port: '22',
    signature_id: '100002',
    signature: 'LAB WEB brute force detected',
    action: 'BLOCKED'
  },
  {
    id: 'evt-1004',
    timestamp: '13:54:31',
    attack_type: 'Port Scan',
    src_ip: '192.168.2.10',
    dest_ip: '192.168.2.100',
    dest_port: '1-1000',
    signature_id: '100001',
    signature: 'LAB Port scan detected',
    action: 'BLOCKED'
  }
];

const timeline = [
  { time: '13:40', portscan: 1, bruteforce: 0, sqli: 0 },
  { time: '13:45', portscan: 0, bruteforce: 1, sqli: 0 },
  { time: '13:50', portscan: 1, bruteforce: 0, sqli: 1 },
  { time: '13:55', portscan: 2, bruteforce: 1, sqli: 0 },
  { time: '14:00', portscan: 1, bruteforce: 0, sqli: 1 },
  { time: '14:05', portscan: 3, bruteforce: 1, sqli: 1 }
];

const attackTypes = [
  { name: 'Port Scan', value: 6, color: '#26d9ff' },
  { name: 'Brute Force', value: 3, color: '#ff4d63' },
  { name: 'SQL Injection', value: 2, color: '#a66cff' }
];

const flowNodes = [
  { label: 'Kali', desc: 'Attacker VM', icon: Terminal },
  { label: 'IPS', desc: 'Suricata + iptables', icon: ShieldAlert },
  { label: 'Web', desc: 'Flask target', icon: Server },
  { label: 'DB', desc: 'MySQL', icon: Database },
  { label: 'Wazuh', desc: 'Manager + Indexer', icon: Radar },
  { label: 'CHANXAI', desc: 'Cloudflare Pages', icon: Network }
];

const scenarios = [
  { id: 'portscan', title: 'Port Scan 실행', icon: ScanLine, color: 'cyan', detail: 'nmap 기반 LAB 스캔 시나리오' },
  { id: 'bruteforce', title: 'Brute Force 실행', icon: Lock, color: 'red', detail: '로그인 엔드포인트 반복 시도' },
  { id: 'sqli', title: 'SQL Injection 실행', icon: Zap, color: 'purple', detail: '고정 URL 대상 SQLi 테스트' },
  { id: 'random', title: '랜덤 공격 실행', icon: Play, color: 'amber', detail: '허용된 시나리오 중 하나 실행' }
];

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [activeScenario, setActiveScenario] = useState(null);
  const [chatMessages, setChatMessages] = useState([
    { role: 'bot', text: 'AI는 allowlist 시나리오만 선택합니다. 포트스캔, 브루트포스, SQL 인젝션, 최근 로그 요약을 요청할 수 있습니다.' }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [events, setEvents] = useState(mockEvents);

  const summary = useMemo(() => {
    const count = (name) => events.filter((event) => event.attack_type === name).length;
    return {
      total: events.length,
      portscan: count('Port Scan'),
      bruteforce: count('Brute Force'),
      sqli: count('SQL Injection'),
      blocked: new Set(events.filter((event) => event.action === 'BLOCKED').map((event) => event.src_ip)).size
    };
  }, [events]);

  const runScenario = (scenarioId) => {
    const scenarioLabel = {
      portscan: 'Port Scan',
      bruteforce: 'Brute Force',
      sqli: 'SQL Injection',
      random: 'Port Scan'
    }[scenarioId];
    const signature = {
      'Port Scan': 'LAB Port scan detected',
      'Brute Force': 'LAB WEB brute force detected',
      'SQL Injection': 'LAB SQL Injection detected'
    }[scenarioLabel];

    setActiveScenario(scenarioId);
    window.setTimeout(() => setActiveScenario(null), 1800);
    setEvents((current) => [
      {
        id: `evt-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString('ko-KR', { hour12: false }),
        attack_type: scenarioLabel,
        src_ip: '192.168.2.10',
        dest_ip: '192.168.2.100',
        dest_port: scenarioLabel === 'SQL Injection' ? '80' : scenarioLabel === 'Brute Force' ? '22' : '22-8080',
        signature_id: scenarioLabel === 'SQL Injection' ? '100003' : scenarioLabel === 'Brute Force' ? '100002' : '100001',
        signature,
        action: scenarioLabel === 'SQL Injection' ? 'ALERT' : 'BLOCKED'
      },
      ...current
    ].slice(0, 8));
  };

  const handleChat = (event) => {
    event.preventDefault();
    const message = chatInput.trim();
    if (!message) return;

    const normalized = message.toLowerCase().replace(/\s+/g, '');
    setChatMessages((current) => [...current, { role: 'user', text: message }]);
    setChatInput('');

    if (['sudo', 'bash', 'curl', 'wget', 'python', ';', '&&', '|'].some((token) => normalized.includes(token))) {
      setChatMessages((current) => [...current, { role: 'bot', text: '임의 명령어는 실행할 수 없습니다. 사전 정의된 안전 시나리오만 선택합니다.' }]);
      return;
    }

    if (normalized.includes('요약') || normalized.includes('summary')) {
      setChatMessages((current) => [...current, { role: 'bot', text: `최근 LAB 이벤트 ${summary.total}건: Port Scan ${summary.portscan}건, Brute Force ${summary.bruteforce}건, SQL Injection ${summary.sqli}건입니다.` }]);
      return;
    }

    const scenario = normalized.includes('sql') || normalized.includes('인젝션')
      ? 'sqli'
      : normalized.includes('brute') || normalized.includes('브루트') || normalized.includes('무차별')
        ? 'bruteforce'
        : normalized.includes('port') || normalized.includes('scan') || normalized.includes('포트') || normalized.includes('스캔')
          ? 'portscan'
          : normalized.includes('공격') || normalized.includes('랜덤')
            ? 'random'
            : null;

    if (!scenario) {
      setChatMessages((current) => [...current, { role: 'bot', text: '요청을 시나리오로 분류하지 못했습니다. 포트스캔, 브루트포스, SQL 인젝션 중 하나로 요청해 주세요.' }]);
      return;
    }

    runScenario(scenario);
    setChatMessages((current) => [...current, { role: 'bot', text: `${scenario} 시나리오를 선택했습니다. 대상 IP는 내부 LAB 서버로 고정됩니다.` }]);
  };

  if (!isLoggedIn) {
    return <LoginScreen onLogin={() => setIsLoggedIn(true)} />;
  }

  return (
    <div className="min-h-screen bg-soc-bg text-slate-100">
      <Header onLogout={() => setIsLoggedIn(false)} />
      <main className="mx-auto grid w-full max-w-[1540px] gap-4 px-4 pb-8 pt-4 lg:px-6">
        <Hero />
        <KpiGrid summary={summary} />
        <section className="grid gap-4 xl:grid-cols-[1.35fr_0.95fr]">
          <NetworkFlow activeScenario={activeScenario} />
          <SimulationPanel activeScenario={activeScenario} onRun={runScenario} />
        </section>
        <section className="grid gap-4 xl:grid-cols-[1.25fr_0.9fr]">
          <EventsPanel events={events} />
          <ChatPanel messages={chatMessages} value={chatInput} onChange={setChatInput} onSubmit={handleChat} />
        </section>
        <section className="grid gap-4 xl:grid-cols-[1fr_0.8fr]">
          <TimelineChart />
          <AttackTypeChart />
        </section>
      </main>
    </div>
  );
}

function LoginScreen({ onLogin }) {
  return (
    <div className="min-h-screen bg-soc-bg text-slate-100">
      <div className="mx-auto grid min-h-screen max-w-6xl items-center gap-8 px-5 py-8 lg:grid-cols-[1.05fr_0.8fr]">
        <section>
          <div className="mb-6 inline-flex items-center gap-2 rounded-md border border-cyan-400/30 bg-cyan-400/10 px-3 py-2 text-sm font-bold text-cyan-200">
            <Shield className="h-4 w-4" /> CHANXAI CAPSTONE SOC
          </div>
          <h1 className="max-w-4xl text-5xl font-black leading-none tracking-normal text-white md:text-7xl">
            AI 기반 IPS + Wazuh 실시간 보안관제 플랫폼
          </h1>
          <p className="mt-5 max-w-2xl text-lg leading-8 text-slate-300">
            Suricata IPS, Wazuh SIEM, Kali 테스트 서버, Web/DB 실험망을 연결해 공격 시뮬레이션부터 탐지 로그 시각화까지 발표용 대시보드로 제공합니다.
          </p>
          <div className="mt-8 grid gap-3 sm:grid-cols-3">
            {['Suricata IPS', 'Wazuh SIEM', 'Safe Simulation'].map((item) => (
              <div key={item} className="rounded-lg border border-soc-line bg-soc-panel/80 p-4 font-bold text-slate-200">{item}</div>
            ))}
          </div>
        </section>

        <section className="rounded-lg border border-soc-line bg-soc-panel p-6 shadow-2xl shadow-black/30">
          <div className="mb-6 flex items-center justify-between">
            <div>
              <p className="text-xs font-black uppercase text-soc-cyan">Administrator</p>
              <h2 className="mt-1 text-2xl font-black">대시보드 로그인</h2>
            </div>
            <User className="h-9 w-9 text-soc-cyan" />
          </div>
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              onLogin();
            }}
          >
            <label className="grid gap-2 text-sm font-bold text-slate-300">
              Admin ID
              <input className="rounded-md border border-soc-line bg-slate-950 px-4 py-3 text-white outline-none focus:border-soc-cyan" defaultValue="admin" />
            </label>
            <label className="grid gap-2 text-sm font-bold text-slate-300">
              Password
              <input className="rounded-md border border-soc-line bg-slate-950 px-4 py-3 text-white outline-none focus:border-soc-cyan" type="password" defaultValue="capstone" />
            </label>
            <button className="mt-2 rounded-md bg-soc-cyan px-4 py-3 font-black text-slate-950 transition hover:bg-cyan-300" type="submit">
              Sign in to SOC Dashboard
            </button>
          </form>
          <p className="mt-4 text-sm text-slate-400">초기 mock 단계입니다. 실제 운영에서는 백엔드 인증 API와 연결합니다.</p>
        </section>
      </div>
    </div>
  );
}

function Header({ onLogout }) {
  return (
    <header className="sticky top-0 z-30 border-b border-soc-line bg-soc-bg/90 backdrop-blur">
      <div className="mx-auto flex max-w-[1540px] flex-col gap-3 px-4 py-4 lg:flex-row lg:items-center lg:justify-between lg:px-6">
        <div>
          <p className="text-xs font-black uppercase text-soc-cyan">chanxai.com security operations center</p>
          <h1 className="text-2xl font-black text-white">IPS + Wazuh 실시간 관제 대시보드</h1>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <span className="rounded-full border border-green-400/40 bg-green-400/10 px-3 py-2 text-sm font-bold text-green-200">Mock Pipeline Online</span>
          <button onClick={onLogout} className="inline-flex items-center gap-2 rounded-md border border-soc-line px-3 py-2 font-bold text-slate-200 hover:bg-white/5">
            <LogOut className="h-4 w-4" /> Logout
          </button>
        </div>
      </div>
    </header>
  );
}

function Hero() {
  return (
    <section className="grid gap-4 rounded-lg border border-soc-line bg-soc-panel p-5 lg:grid-cols-[1fr_0.65fr]">
      <div>
        <p className="text-xs font-black uppercase text-soc-cyan">Project Overview</p>
        <h2 className="mt-2 text-3xl font-black text-white lg:text-4xl">Suricata 탐지부터 Wazuh 수집, CHANXAI 시각화까지</h2>
        <p className="mt-3 max-w-4xl leading-7 text-slate-300">
          이 화면은 실제 공격 플랫폼이 아니라 캡스톤 발표용 보안관제 시뮬레이션 UI입니다. 공격 대상은 내부 LAB 서버로 고정하고, AI와 버튼은 allowlist 시나리오만 실행하도록 설계합니다.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <StatusTile label="IPS Server" value="192.168.2.1" />
        <StatusTile label="Web Target" value="192.168.2.100" />
        <StatusTile label="Wazuh" value="192.168.2.150" />
        <StatusTile label="Deploy" value="Cloudflare Pages" />
      </div>
    </section>
  );
}

function StatusTile({ label, value }) {
  return (
    <div className="rounded-lg border border-soc-line bg-slate-950/50 p-4">
      <p className="text-xs font-bold uppercase text-slate-500">{label}</p>
      <p className="mt-2 font-mono text-sm font-bold text-slate-100">{value}</p>
    </div>
  );
}

function KpiGrid({ summary }) {
  const items = [
    { label: 'Total Events', value: summary.total, icon: Activity, color: 'text-soc-blue' },
    { label: 'Port Scan', value: summary.portscan, icon: ScanLine, color: 'text-soc-cyan' },
    { label: 'Brute Force', value: summary.bruteforce, icon: Lock, color: 'text-soc-red' },
    { label: 'SQL Injection', value: summary.sqli, icon: Zap, color: 'text-soc-purple' },
    { label: 'Blocked IPs', value: summary.blocked, icon: ShieldAlert, color: 'text-soc-amber' }
  ];
  return (
    <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
      {items.map((item) => {
        const Icon = item.icon;
        return (
          <article key={item.label} className="rounded-lg border border-soc-line bg-soc-panel p-5">
            <div className="flex items-center justify-between">
              <p className="font-bold text-slate-400">{item.label}</p>
              <Icon className={`h-5 w-5 ${item.color}`} />
            </div>
            <strong className="mt-4 block text-4xl font-black text-white">{item.value}</strong>
            <span className="mt-2 block text-sm text-slate-500">LAB 룰 중심 mock telemetry</span>
          </article>
        );
      })}
    </section>
  );
}

function NetworkFlow({ activeScenario }) {
  return (
    <section className="rounded-lg border border-soc-line bg-soc-panel p-5">
      <PanelTitle eyebrow="Network Flow" title="Kali → IPS → Wazuh → Dashboard" icon={Network} />
      <div className="mt-5 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        {flowNodes.map((node, index) => {
          const Icon = node.icon;
          const active = Boolean(activeScenario);
          return (
            <div key={node.label} className={`relative rounded-lg border p-4 ${active ? 'border-soc-cyan bg-cyan-400/10' : 'border-soc-line bg-slate-950/50'}`}>
              <div className="mb-3 flex items-center justify-between">
                <Icon className="h-5 w-5 text-soc-cyan" />
                <span className="font-mono text-xs font-bold text-slate-500">0{index + 1}</span>
              </div>
              <strong className="block text-white">{node.label}</strong>
              <small className="mt-1 block text-slate-400">{node.desc}</small>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function SimulationPanel({ activeScenario, onRun }) {
  return (
    <section className="rounded-lg border border-soc-line bg-soc-panel p-5">
      <PanelTitle eyebrow="Simulation" title="안전한 공격 시뮬레이션" icon={Play} />
      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        {scenarios.map((scenario) => {
          const Icon = scenario.icon;
          const running = activeScenario === scenario.id;
          return (
            <button key={scenario.id} onClick={() => onRun(scenario.id)} className={`rounded-lg border p-4 text-left transition hover:-translate-y-0.5 ${running ? 'border-soc-cyan bg-cyan-400/10' : 'border-soc-line bg-slate-950/50 hover:bg-white/5'}`}>
              <Icon className="mb-3 h-5 w-5 text-soc-cyan" />
              <strong className="block text-white">{scenario.title}</strong>
              <span className="mt-1 block text-sm text-slate-400">{scenario.detail}</span>
            </button>
          );
        })}
      </div>
      <div className="mt-4 flex flex-wrap gap-2 text-xs font-bold text-green-200">
        <span className="rounded-full border border-green-400/30 bg-green-400/10 px-3 py-1">allowlist only</span>
        <span className="rounded-full border border-green-400/30 bg-green-400/10 px-3 py-1">fixed target IP</span>
        <span className="rounded-full border border-green-400/30 bg-green-400/10 px-3 py-1">mock mode</span>
      </div>
    </section>
  );
}

function EventsPanel({ events }) {
  return (
    <section className="rounded-lg border border-soc-line bg-soc-panel p-5">
      <PanelTitle eyebrow="Wazuh / Suricata Events" title="실시간 탐지 이벤트" icon={ShieldAlert} />
      <div className="mt-5 overflow-x-auto rounded-lg border border-soc-line">
        <table className="w-full min-w-[920px] border-collapse font-mono text-sm">
          <thead className="bg-slate-950 text-left text-slate-300">
            <tr>
              {['time', 'attack_type', 'src_ip', 'dest_ip', 'port', 'sid', 'signature', 'action'].map((head) => <th key={head} className="px-3 py-3">{head}</th>)}
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id} className="border-t border-soc-line text-slate-200">
                <td className="px-3 py-3">{event.timestamp}</td>
                <td className="px-3 py-3"><TypePill type={event.attack_type} /></td>
                <td className="px-3 py-3">{event.src_ip}</td>
                <td className="px-3 py-3">{event.dest_ip}</td>
                <td className="px-3 py-3">{event.dest_port}</td>
                <td className="px-3 py-3">{event.signature_id}</td>
                <td className="px-3 py-3">{event.signature}</td>
                <td className="px-3 py-3"><span className={event.action === 'BLOCKED' ? 'text-soc-amber' : 'text-soc-red'}>{event.action}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ChatPanel({ messages, value, onChange, onSubmit }) {
  return (
    <section className="grid rounded-lg border border-soc-line bg-soc-panel p-5">
      <PanelTitle eyebrow="AI Operator" title="시나리오 챗봇" icon={Bot} />
      <div className="mt-5 grid max-h-[380px] content-start gap-3 overflow-auto pr-1">
        {messages.map((message, index) => (
          <div key={`${message.role}-${index}`} className={`max-w-[92%] rounded-lg border px-3 py-2 text-sm leading-6 ${message.role === 'user' ? 'justify-self-end border-cyan-400/30 bg-cyan-400/10 text-cyan-50' : 'justify-self-start border-soc-line bg-slate-950/70 text-slate-200'}`}>
            {message.text}
          </div>
        ))}
      </div>
      <form onSubmit={onSubmit} className="mt-4 grid gap-2 sm:grid-cols-[1fr_auto]">
        <input value={value} onChange={(event) => onChange(event.target.value)} className="rounded-md border border-soc-line bg-slate-950 px-4 py-3 text-white outline-none focus:border-soc-cyan" placeholder="예: 포트스캔 실행해줘, 최근 로그 요약해줘" />
        <button className="rounded-md bg-soc-cyan px-5 py-3 font-black text-slate-950" type="submit">Send</button>
      </form>
    </section>
  );
}

function TimelineChart() {
  return (
    <section className="rounded-lg border border-soc-line bg-soc-panel p-5">
      <PanelTitle eyebrow="Timeline" title="시간대별 탐지 그래프" icon={Activity} />
      <div className="mt-5 h-72">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={timeline}>
            <CartesianGrid stroke="#213447" strokeDasharray="3 3" />
            <XAxis dataKey="time" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" />
            <Tooltip contentStyle={{ background: '#0d1824', border: '1px solid #213447', color: '#fff' }} />
            <Area type="monotone" dataKey="portscan" stackId="1" stroke="#26d9ff" fill="#26d9ff" fillOpacity={0.35} />
            <Area type="monotone" dataKey="bruteforce" stackId="1" stroke="#ff4d63" fill="#ff4d63" fillOpacity={0.35} />
            <Area type="monotone" dataKey="sqli" stackId="1" stroke="#a66cff" fill="#a66cff" fillOpacity={0.35} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}

function AttackTypeChart() {
  return (
    <section className="rounded-lg border border-soc-line bg-soc-panel p-5">
      <PanelTitle eyebrow="Attack Types" title="공격 유형별 분포" icon={Radar} />
      <div className="mt-5 grid gap-4 lg:grid-cols-[0.8fr_1fr]">
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={attackTypes} dataKey="value" nameKey="name" innerRadius={58} outerRadius={92} paddingAngle={4}>
                {attackTypes.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#0d1824', border: '1px solid #213447', color: '#fff' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={attackTypes} layout="vertical">
              <CartesianGrid stroke="#213447" strokeDasharray="3 3" />
              <XAxis type="number" stroke="#94a3b8" />
              <YAxis type="category" dataKey="name" stroke="#94a3b8" width={94} />
              <Tooltip contentStyle={{ background: '#0d1824', border: '1px solid #213447', color: '#fff' }} />
              <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                {attackTypes.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </section>
  );
}

function PanelTitle({ eyebrow, title, icon: Icon }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <div>
        <p className="text-xs font-black uppercase text-soc-cyan">{eyebrow}</p>
        <h2 className="mt-1 text-xl font-black text-white">{title}</h2>
      </div>
      <Icon className="h-6 w-6 text-soc-cyan" />
    </div>
  );
}

function TypePill({ type }) {
  const className = type === 'Port Scan'
    ? 'bg-cyan-400 text-slate-950'
    : type === 'Brute Force'
      ? 'bg-rose-400 text-slate-950'
      : 'bg-purple-400 text-slate-950';
  return <span className={`rounded-full px-2 py-1 text-xs font-black ${className}`}>{type}</span>;
}

export default App;
