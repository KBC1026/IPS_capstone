import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Bot,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
  Database,
  FileJson,
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
  X,
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
import { api } from './api';

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
  {
    id: 'kali',
    label: 'Kali',
    desc: 'Attack Simulation VM',
    icon: Terminal,
    ip: '117.16.174.60',
    role: '허용된 공격 시나리오를 실행하는 테스트 VM입니다.',
    services: ['port_scan_blocked.py', 'brute_force_blocked.py', 'sql_injection_blocked.py'],
    telemetry: 'Port Scan, Brute Force, SQL Injection 테스트 트래픽을 Web/IPS 구간으로 발생시킵니다.',
    security: '대상은 LAB 서버로 고정하고, 대시보드 API는 allowlist 시나리오만 SSH로 실행합니다.'
  },
  {
    id: 'ips',
    label: 'IPS',
    desc: 'Suricata + iptables',
    icon: ShieldAlert,
    ip: '192.168.2.1',
    role: 'Kali와 서비스 서버 사이에서 트래픽을 감시하고 차단하는 보안 게이트웨이입니다.',
    services: ['Suricata IDS/IPS', 'iptables block rule', 'AI detector'],
    telemetry: 'Suricata alert, AI 탐지 로그, 차단 IP 이벤트를 Wazuh 수집 대상으로 전달합니다.',
    security: '룰 기반 탐지와 AI 보조 탐지를 함께 사용하며 반복 공격 IP는 차단 후보가 됩니다.'
  },
  {
    id: 'web',
    label: 'Web',
    desc: 'Flask Target Server',
    icon: Server,
    ip: '192.168.2.100',
    role: '로그인 서비스와 공격 테스트 대상 엔드포인트를 제공하는 웹 서버입니다.',
    services: ['Flask login app', '/login endpoint', 'access/auth logs'],
    telemetry: '로그인 실패, SQLi 의심 입력, HTTP 요청 결과를 이벤트 분석에 사용합니다.',
    security: '계정 잠금, 입력 검증, 요청 로그 저장을 통해 공격 흔적을 남깁니다.'
  },
  {
    id: 'db',
    label: 'DB',
    desc: 'MySQL Data Store',
    icon: Database,
    ip: '192.168.2.110',
    role: '웹 서비스의 사용자 정보와 로그인 로그를 저장하는 데이터베이스 서버입니다.',
    services: ['MySQL', 'login_db', 'auth_log table'],
    telemetry: '인증 성공/실패 기록과 계정 잠금 상태를 보안 분석 근거로 제공합니다.',
    security: '웹 서버에서만 접근하도록 제한하고 최소 권한 DB 계정을 사용하는 구성이 적합합니다.'
  },
  {
    id: 'wazuh',
    label: 'Wazuh',
    desc: 'Manager + Indexer',
    icon: Radar,
    ip: '192.168.2.150',
    role: '보안 이벤트를 중앙 수집, 검색, 상관분석하는 SIEM 서버입니다.',
    services: ['Wazuh Manager', 'Wazuh Indexer', 'Wazuh API'],
    telemetry: 'Suricata alert와 서버 로그를 인덱싱하고 대시보드 API가 최근 이벤트를 조회합니다.',
    security: 'LAB 이벤트 필터링, 탐지 룰 이름, 위험도, Source/Destination 정보를 제공합니다.'
  },
  {
    id: 'dashboard',
    label: 'CHANXAI',
    desc: 'SOC Dashboard',
    icon: Network,
    ip: 'chanxai.com',
    role: '관제 사용자가 이벤트를 조회하고 시뮬레이션을 실행하는 프론트엔드입니다.',
    services: ['Cloudflare Pages', 'api.chanxai.com', 'React dashboard'],
    telemetry: 'Wazuh API 이벤트, AI 요약, 시나리오 실행 결과를 SOC 화면에 시각화합니다.',
    security: '새 탭 이동 없이 모달과 패널로 상세 분석을 제공하고 API 호출은 백엔드로 제한합니다.'
  }
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
  const [timelineData, setTimelineData] = useState(timeline);
  const [apiStatus, setApiStatus] = useState('Connecting API');
  const [wazuhHealth, setWazuhHealth] = useState(null);
  const [summaryData, setSummaryData] = useState(null);
  const [labOnly, setLabOnly] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState(null);

  const calculatedSummary = useMemo(() => {
    const count = (name) => events.filter((event) => event.attack_type === name).length;
    return {
      total: events.length,
      portscan: count('Port Scan'),
      bruteforce: count('Brute Force'),
      sqli: count('SQL Injection'),
      blocked: new Set(events.filter((event) => event.action === 'BLOCKED').map((event) => event.src_ip)).size
    };
  }, [events]);

  const summary = summaryData || calculatedSummary;

  const attackTypeData = useMemo(() => [
    { name: 'Port Scan', value: summary.portscan, color: '#26d9ff' },
    { name: 'Brute Force', value: summary.bruteforce, color: '#ff4d63' },
    { name: 'SQL Injection', value: summary.sqli, color: '#a66cff' }
  ], [summary]);

  const refreshSecurityData = async () => {
    try {
      const [healthPayload, eventPayload, timelinePayload, summaryPayload] = await Promise.all([
        api.health(),
        api.events(50, { labOnly }),
        api.timeline({ labOnly }),
        api.summary({ labOnly })
      ]);
      const health = healthPayload.wazuh || {};
      setWazuhHealth(health);
      setApiStatus(health.source === 'wazuh-api' ? 'Wazuh API Online' : health.indexer?.ok ? 'Wazuh Indexer Online' : 'API Online / Wazuh Offline');
      if (Array.isArray(eventPayload.events)) {
        setEvents(eventPayload.events);
      }
      if (Array.isArray(timelinePayload.timeline) && timelinePayload.timeline.length > 0) {
        setTimelineData(timelinePayload.timeline);
      }
      setSummaryData(summaryPayload);
    } catch (error) {
      setApiStatus('Backend Offline');
      setWazuhHealth(null);
      setSummaryData(null);
    }
  };

  useEffect(() => {
    refreshSecurityData();
    const timer = window.setInterval(refreshSecurityData, 5000);
    return () => window.clearInterval(timer);
  }, [labOnly]);

  const runScenario = async (scenarioId) => {
    setActiveScenario(scenarioId);
    window.setTimeout(() => setActiveScenario(null), 1800);

    try {
      const result = await api.runSimulation(scenarioId);
      setChatMessages((current) => [...current, { role: 'bot', text: result.message }]);
      window.setTimeout(refreshSecurityData, 1200);
    } catch (error) {
      setChatMessages((current) => [...current, { role: 'bot', text: error.message }]);
    }
  };

  const handleChat = async (event) => {
    event.preventDefault();
    const message = chatInput.trim();
    if (!message) return;

    const normalized = message.toLowerCase().replace(/\s+/g, '');
    setChatMessages((current) => [...current, { role: 'user', text: message }]);
    setChatInput('');

    try {
      const response = await api.chat(message);
      if (response.intent?.action === 'simulate') {
        setActiveScenario(response.intent.scenario);
        window.setTimeout(() => setActiveScenario(null), 1800);
        window.setTimeout(refreshSecurityData, 1200);
      }
      if (Array.isArray(response.events)) {
        setEvents(response.events);
      }
      setChatMessages((current) => [...current, { role: 'bot', text: response.reply }]);
      return;
    } catch (error) {
      // Fall through to local demo handling when the API is offline.
    }

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
      <Header apiStatus={apiStatus} onLogout={() => setIsLoggedIn(false)} />
      <main className="mx-auto grid w-full max-w-[1540px] gap-4 px-4 pb-8 pt-4 lg:px-6">
        <Hero />
        <KpiGrid summary={summary} labOnly={labOnly} />
        <SystemStatus apiStatus={apiStatus} health={wazuhHealth} labOnly={labOnly} onToggleLabOnly={setLabOnly} />
        <section className="grid gap-4 xl:grid-cols-[1.35fr_0.95fr]">
          <NetworkFlow activeScenario={activeScenario} />
          <SimulationPanel activeScenario={activeScenario} onRun={runScenario} />
        </section>
        <section className="grid gap-4 xl:grid-cols-[1.25fr_0.9fr]">
          <EventsPanel events={events} onSelectEvent={setSelectedEvent} />
          <ChatPanel messages={chatMessages} value={chatInput} onChange={setChatInput} onSubmit={handleChat} />
        </section>
        <section className="grid gap-4 xl:grid-cols-[1fr_0.8fr]">
          <TimelineChart data={timelineData} />
          <AttackTypeChart data={attackTypeData} />
        </section>
      </main>
      <EventDetailModal event={selectedEvent} onClose={() => setSelectedEvent(null)} />
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
          <p className="mt-4 text-sm text-slate-400">로그인 후 api.chanxai.com을 통해 Wazuh Indexer 이벤트를 조회합니다.</p>
        </section>
      </div>
    </div>
  );
}

function Header({ apiStatus, onLogout }) {
  return (
    <header className="sticky top-0 z-30 border-b border-soc-line bg-soc-bg/90 backdrop-blur">
      <div className="mx-auto flex max-w-[1540px] flex-col gap-3 px-4 py-4 lg:flex-row lg:items-center lg:justify-between lg:px-6">
        <div>
          <p className="text-xs font-black uppercase text-soc-cyan">chanxai.com security operations center</p>
          <h1 className="text-2xl font-black text-white">IPS + Wazuh 실시간 관제 대시보드</h1>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <span className="rounded-full border border-green-400/40 bg-green-400/10 px-3 py-2 text-sm font-bold text-green-200">{apiStatus}</span>
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

function SystemStatus({ apiStatus, health, labOnly, onToggleLabOnly }) {
  const indexerStatus = health?.indexer?.status || (health?.indexer?.ok ? 'connected' : 'unknown');
  const agentsSeen = health?.agents_seen ?? '-';
  const demoFallback = health?.demo_fallback ? 'enabled' : 'false';
  const statusItems = [
    { label: 'Backend API', value: apiStatus, tone: apiStatus.includes('Offline') ? 'text-soc-red' : 'text-soc-green' },
    { label: 'Wazuh API', value: health?.source === 'wazuh-api' ? 'online' : 'degraded', tone: health?.source === 'wazuh-api' ? 'text-soc-green' : 'text-soc-amber' },
    { label: 'Indexer', value: indexerStatus, tone: indexerStatus === 'green' ? 'text-soc-green' : 'text-soc-amber' },
    { label: 'Agents', value: agentsSeen, tone: 'text-soc-cyan' },
    { label: 'Demo Fallback', value: demoFallback, tone: health?.demo_fallback ? 'text-soc-amber' : 'text-soc-green' }
  ];

  return (
    <section className="grid gap-4 rounded-lg border border-soc-line bg-soc-panel p-5 xl:grid-cols-[1fr_auto]">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {statusItems.map((item) => (
          <div key={item.label} className="rounded-lg border border-soc-line bg-slate-950/50 p-4">
            <p className="text-xs font-bold uppercase text-slate-500">{item.label}</p>
            <p className={`mt-2 font-mono text-sm font-black ${item.tone}`}>{item.value}</p>
          </div>
        ))}
      </div>
      <div className="flex items-center gap-2 justify-self-start xl:justify-self-end">
        <button
          type="button"
          onClick={() => onToggleLabOnly(true)}
          className={`rounded-md border px-4 py-3 text-sm font-black ${labOnly ? 'border-soc-cyan bg-cyan-400/15 text-cyan-100' : 'border-soc-line bg-slate-950/50 text-slate-300'}`}
        >
          LAB 이벤트
        </button>
        <button
          type="button"
          onClick={() => onToggleLabOnly(false)}
          className={`rounded-md border px-4 py-3 text-sm font-black ${!labOnly ? 'border-soc-cyan bg-cyan-400/15 text-cyan-100' : 'border-soc-line bg-slate-950/50 text-slate-300'}`}
        >
          전체 보기
        </button>
      </div>
    </section>
  );
}

function KpiGrid({ summary, labOnly }) {
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
            <span className="mt-2 block text-sm text-slate-500">{labOnly ? 'LAB 이벤트 중심' : '전체 로그'} Wazuh telemetry</span>
          </article>
        );
      })}
    </section>
  );
}

function NetworkFlow({ activeScenario }) {
  const [selectedNodeId, setSelectedNodeId] = useState(flowNodes[0].id);
  const selectedNode = flowNodes.find((node) => node.id === selectedNodeId) || flowNodes[0];
  const SelectedIcon = selectedNode.icon;

  return (
    <section className="rounded-lg border border-soc-line bg-soc-panel p-5">
      <PanelTitle eyebrow="Network Flow" title="VM 조직도: Kali → IPS → Wazuh → Dashboard" icon={Network} />
      <div className="mt-5 grid gap-4">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
            {flowNodes.map((node, index) => {
              const Icon = node.icon;
              const selected = selectedNodeId === node.id;
              const running = Boolean(activeScenario);
              return (
                <button
                  key={node.id}
                  type="button"
                  onClick={() => setSelectedNodeId(node.id)}
                  className={`relative min-h-32 rounded-lg border p-4 text-left outline-none transition hover:-translate-y-0.5 hover:bg-white/5 focus:ring-2 focus:ring-soc-cyan/70 ${selected ? 'border-soc-cyan bg-cyan-400/10 shadow-lg shadow-cyan-950/20' : running ? 'border-soc-amber/60 bg-amber-400/5' : 'border-soc-line bg-slate-950/50'}`}
                >
                  <div className="mb-3 flex items-center justify-between">
                    <Icon className="h-5 w-5 text-soc-cyan" />
                    <span className="font-mono text-xs font-bold text-slate-500">0{index + 1}</span>
                  </div>
                  <strong className="block break-words text-white">{node.label}</strong>
                  <small className="mt-1 block min-h-10 text-sm leading-5 text-slate-400">{node.desc}</small>
                  <span className="mt-3 block break-all font-mono text-xs font-bold text-slate-500">{node.ip}</span>
                  {index < flowNodes.length - 1 && (
                    <span className="pointer-events-none absolute -right-2 top-1/2 hidden h-px w-4 bg-soc-line xl:block" aria-hidden="true" />
                  )}
                </button>
              );
            })}
        </div>

        <div className="grid gap-2 rounded-lg border border-soc-line bg-slate-950/40 p-4 sm:grid-cols-3">
          <FlowStep label="01 Generate" value="Kali 공격 테스트 트래픽 생성" />
          <FlowStep label="02 Detect" value="IPS/Suricata/AI 탐지 및 차단" />
          <FlowStep label="03 Observe" value="Wazuh 수집 후 Dashboard 표시" />
        </div>

        <aside className="rounded-lg border border-soc-line bg-slate-950/50 p-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-black uppercase text-soc-cyan">Selected VM</p>
              <h3 className="mt-1 text-xl font-black text-white">{selectedNode.label}</h3>
            </div>
            <SelectedIcon className="h-7 w-7 text-soc-cyan" />
          </div>
          <dl className="mt-5 grid gap-4 md:grid-cols-2">
            <NodeDetail label="Address" value={selectedNode.ip} mono />
            <NodeDetail label="Role" value={selectedNode.role} />
            <NodeDetail label="Telemetry" value={selectedNode.telemetry} />
            <NodeDetail label="Security Note" value={selectedNode.security} />
          </dl>
          <div className="mt-4">
            <p className="text-xs font-black uppercase text-slate-500">Services</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {selectedNode.services.map((service) => (
                <span key={service} className="rounded-full border border-soc-line bg-soc-panel px-3 py-1 font-mono text-xs font-bold text-slate-300">{service}</span>
              ))}
            </div>
          </div>
        </aside>
      </div>
    </section>
  );
}

function FlowStep({ label, value }) {
  return (
    <div className="rounded-md border border-soc-line bg-soc-panel/80 p-3">
      <p className="font-mono text-xs font-black text-soc-cyan">{label}</p>
      <p className="mt-1 text-sm font-bold text-slate-200">{value}</p>
    </div>
  );
}

function NodeDetail({ label, value, mono = false }) {
  return (
    <div>
      <dt className="text-xs font-black uppercase text-slate-500">{label}</dt>
      <dd className={`mt-1 leading-6 text-slate-200 ${mono ? 'font-mono text-sm font-bold' : 'text-sm'}`}>{value}</dd>
    </div>
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
        <span className="rounded-full border border-green-400/30 bg-green-400/10 px-3 py-1">api-triggered</span>
      </div>
    </section>
  );
}

function EventsPanel({ events, onSelectEvent }) {
  const pageSize = 8;
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(events.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const startIndex = (currentPage - 1) * pageSize;
  const pageEvents = events.slice(startIndex, startIndex + pageSize);

  useEffect(() => {
    setPage(1);
  }, [events]);

  const goToPage = (nextPage) => {
    setPage(Math.min(totalPages, Math.max(1, nextPage)));
  };

  return (
    <section className="rounded-lg border border-soc-line bg-soc-panel p-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <PanelTitle eyebrow="Wazuh / Suricata Events" title="실시간 탐지 이벤트" icon={ShieldAlert} />
        <div className="flex flex-wrap items-center gap-2 text-sm text-slate-400">
          <span className="font-mono">{events.length} events</span>
          <span className="font-mono">{currentPage} / {totalPages}</span>
        </div>
      </div>
      <div className="mt-5 overflow-x-auto rounded-lg border border-soc-line">
        <table className="w-full min-w-[920px] border-collapse font-mono text-sm">
          <thead className="bg-slate-950 text-left text-slate-300">
            <tr>
              {['time', 'attack_type', 'src_ip', 'dest_ip', 'port', 'sid', 'severity', 'signature', 'action'].map((head) => <th key={head} className="px-3 py-3">{head}</th>)}
            </tr>
          </thead>
          <tbody>
            {events.length === 0 && (
              <tr className="border-t border-soc-line text-slate-400">
                <td className="px-3 py-6 text-center" colSpan={9}>표시할 이벤트가 없습니다.</td>
              </tr>
            )}
            {pageEvents.map((event) => (
              <tr
                key={event.id}
                tabIndex={0}
                role="button"
                onClick={() => onSelectEvent(event)}
                onKeyDown={(keyboardEvent) => {
                  if (keyboardEvent.key === 'Enter' || keyboardEvent.key === ' ') {
                    keyboardEvent.preventDefault();
                    onSelectEvent(event);
                  }
                }}
                className="border-t border-soc-line text-slate-200 outline-none transition hover:bg-cyan-400/5 focus:bg-cyan-400/10 focus:ring-2 focus:ring-inset focus:ring-soc-cyan/60"
              >
                <td className="px-3 py-3">{event.timestamp}</td>
                <td className="px-3 py-3"><TypePill type={event.attack_type} /></td>
                <td className="px-3 py-3">{event.src_ip}</td>
                <td className="px-3 py-3">{event.dest_ip}</td>
                <td className="px-3 py-3">{event.dest_port}</td>
                <td className="px-3 py-3">{event.signature_id}</td>
                <td className="px-3 py-3">{event.severity ?? '-'}</td>
                <td className="max-w-[340px] truncate px-3 py-3" title={event.signature}>{event.signature}</td>
                <td className="px-3 py-3"><span className={event.action === 'BLOCKED' ? 'text-soc-amber' : 'text-soc-red'}>{event.action}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm text-slate-500">페이지당 {pageSize}건 표시</p>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => goToPage(currentPage - 1)}
            disabled={currentPage === 1}
            className="inline-flex h-10 w-10 items-center justify-center rounded-md border border-soc-line bg-slate-950/50 text-slate-200 transition hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-40"
            aria-label="이전 페이지"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          {Array.from({ length: totalPages }, (_, index) => index + 1).map((pageNumber) => (
            <button
              key={pageNumber}
              type="button"
              onClick={() => goToPage(pageNumber)}
              className={`h-10 min-w-10 rounded-md border px-3 font-mono text-sm font-black transition ${pageNumber === currentPage ? 'border-soc-cyan bg-cyan-400/15 text-cyan-100' : 'border-soc-line bg-slate-950/50 text-slate-300 hover:bg-white/5'}`}
            >
              {pageNumber}
            </button>
          ))}
          <button
            type="button"
            onClick={() => goToPage(currentPage + 1)}
            disabled={currentPage === totalPages}
            className="inline-flex h-10 w-10 items-center justify-center rounded-md border border-soc-line bg-slate-950/50 text-slate-200 transition hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-40"
            aria-label="다음 페이지"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </section>
  );
}

function EventDetailModal({ event, onClose }) {
  const [showRawJson, setShowRawJson] = useState(false);

  useEffect(() => {
    setShowRawJson(false);
  }, [event]);

  useEffect(() => {
    if (!event) return undefined;

    const previousOverflow = document.body.style.overflow;
    const handleEscape = (keyboardEvent) => {
      if (keyboardEvent.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('keydown', handleEscape);
    document.body.style.overflow = 'hidden';

    return () => {
      document.removeEventListener('keydown', handleEscape);
      document.body.style.overflow = previousOverflow;
    };
  }, [event, onClose]);

  if (!event) return null;

  const severity = normalizeSeverity(event);
  const protocol = event.protocol || inferProtocol(event.dest_port);
  const aiSummary = buildAiSummary(event, severity);
  const aiModelMetrics = buildAiModelMetrics();
  const eventInfo = [
    { label: '탐지 시간', value: event.timestamp || '-' },
    { label: 'Source IP', value: event.src_ip || '-' },
    { label: 'Destination IP', value: event.dest_ip || '-' },
    { label: 'Destination Port', value: event.dest_port || '-' },
    { label: 'Protocol', value: protocol },
    { label: '탐지 룰 이름', value: event.signature || '-' },
    { label: 'Signature ID', value: event.signature_id || '-' },
    { label: 'Action', value: event.action || '-' }
  ];

  return (
    <div
      className="fixed inset-0 z-50 flex min-h-screen items-center justify-center bg-black/70 px-3 py-4 backdrop-blur-sm sm:px-5"
      onMouseDown={onClose}
      aria-labelledby="event-detail-title"
      role="dialog"
      aria-modal="true"
    >
      <section
        className="max-h-[92vh] w-full max-w-5xl overflow-hidden rounded-lg border border-soc-line bg-soc-panel shadow-2xl shadow-black/60"
        onMouseDown={(mouseEvent) => mouseEvent.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3 border-b border-soc-line bg-slate-950/40 px-4 py-4 sm:px-6">
          <div className="min-w-0">
            <p className="text-xs font-black uppercase text-soc-cyan">Event Detail Modal</p>
            <div className="mt-2 flex flex-wrap items-center gap-3">
              <h2 id="event-detail-title" className="text-2xl font-black text-white">{event.attack_type || 'Unknown Event'}</h2>
              <SeverityBadge severity={severity} />
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-soc-line bg-slate-950/70 text-slate-200 transition hover:bg-white/10"
            aria-label="이벤트 상세 모달 닫기"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="max-h-[calc(92vh-73px)] overflow-y-auto px-4 py-5 sm:px-6">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {eventInfo.map((item) => (
              <div key={item.label} className="rounded-lg border border-soc-line bg-slate-950/50 p-4">
                <p className="text-xs font-bold uppercase text-slate-500">{item.label}</p>
                <p className="mt-2 break-words font-mono text-sm font-bold text-slate-100">{item.value}</p>
              </div>
            ))}
          </div>

          <section className="mt-5 rounded-lg border border-soc-line bg-slate-950/35 p-4 sm:p-5">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-xs font-black uppercase text-soc-cyan">AI Analysis Summary</p>
                <h3 className="mt-1 text-lg font-black text-white">AI 분석 요약</h3>
              </div>
              <span className="rounded-full border border-cyan-400/30 bg-cyan-400/10 px-3 py-1 text-xs font-black text-cyan-100">SOC triage</span>
            </div>
            <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              {aiModelMetrics.map((item) => (
                <article key={item.label} className="rounded-lg border border-soc-line bg-slate-950/55 p-4">
                  <p className="text-xs font-black uppercase text-slate-500">{item.label}</p>
                  <strong className="mt-2 block font-mono text-xl font-black text-white">{item.value}</strong>
                  <span className="mt-1 block text-xs leading-5 text-slate-400">{item.detail}</span>
                </article>
              ))}
            </div>
            <div className="mt-3 grid gap-3 lg:grid-cols-2">
              {aiSummary.map((item) => (
                <article key={item.label} className="rounded-lg border border-soc-line bg-soc-panel2 p-4">
                  <p className="text-xs font-black uppercase text-slate-500">{item.label}</p>
                  <p className="mt-2 leading-6 text-slate-200">{item.value}</p>
                </article>
              ))}
            </div>
          </section>

          {showRawJson && (
            <pre className="mt-5 max-h-72 overflow-auto rounded-lg border border-soc-line bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-200">
              {JSON.stringify(event, null, 2)}
            </pre>
          )}

          <div className="mt-5 flex flex-col gap-3 border-t border-soc-line pt-5 sm:flex-row sm:justify-end">
            <button
              type="button"
              onClick={() => setShowRawJson((current) => !current)}
              className="inline-flex items-center justify-center gap-2 rounded-md border border-soc-line bg-slate-950/70 px-4 py-3 font-black text-slate-200 transition hover:bg-white/5"
            >
              <FileJson className="h-4 w-4" /> Raw JSON 보기
            </button>
            <button
              type="button"
              className="inline-flex items-center justify-center gap-2 rounded-md border border-red-400/40 bg-red-400/10 px-4 py-3 font-black text-red-100 transition hover:bg-red-400/20"
            >
              <ShieldAlert className="h-4 w-4" /> IP 차단
            </button>
            <button
              type="button"
              onClick={onClose}
              className="inline-flex items-center justify-center gap-2 rounded-md bg-soc-cyan px-4 py-3 font-black text-slate-950 transition hover:bg-cyan-300"
            >
              <CheckCircle2 className="h-4 w-4" /> 확인 완료
            </button>
          </div>
        </div>
      </section>
    </div>
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

function TimelineChart({ data = timeline }) {
  return (
    <section className="rounded-lg border border-soc-line bg-soc-panel p-5">
      <PanelTitle eyebrow="Timeline" title="시간대별 탐지 그래프" icon={Activity} />
      <div className="mt-5 h-72">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <CartesianGrid stroke="#213447" strokeDasharray="3 3" />
            <XAxis dataKey="time" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" domain={[0, 200]} ticks={[0, 50, 100, 150, 200]} />
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

function AttackTypeChart({ data = attackTypes }) {
  return (
    <section className="rounded-lg border border-soc-line bg-soc-panel p-5">
      <PanelTitle eyebrow="Attack Types" title="공격 유형별 분포" icon={Radar} />
      <div className="mt-5 grid gap-4 lg:grid-cols-[0.8fr_1fr]">
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={data} dataKey="value" nameKey="name" innerRadius={58} outerRadius={92} paddingAngle={4}>
                {data.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#0d1824', border: '1px solid #213447', color: '#fff' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical">
              <CartesianGrid stroke="#213447" strokeDasharray="3 3" />
              <XAxis type="number" stroke="#94a3b8" />
              <YAxis type="category" dataKey="name" stroke="#94a3b8" width={94} />
              <Tooltip contentStyle={{ background: '#0d1824', border: '1px solid #213447', color: '#fff' }} />
              <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                {data.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
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


function SeverityBadge({ severity }) {
  const className = severity === 'Low'
    ? 'border-green-400/40 bg-green-400/15 text-green-200'
    : severity === 'Medium'
      ? 'border-yellow-300/40 bg-yellow-300/15 text-yellow-100'
      : severity === 'High'
        ? 'border-orange-400/40 bg-orange-400/15 text-orange-100'
        : 'border-red-400/50 bg-red-400/15 text-red-100';
  return <span className={`rounded-full border px-3 py-1 text-xs font-black uppercase ${className}`}>{severity}</span>;
}

function normalizeSeverity(event) {
  const raw = String(event.severity || '').toLowerCase();
  if (['low', 'medium', 'high', 'critical'].includes(raw)) {
    return raw.charAt(0).toUpperCase() + raw.slice(1);
  }

  if (event.attack_type === 'SQL Injection') return 'Critical';
  if (event.attack_type === 'Brute Force') return event.action === 'BLOCKED' ? 'High' : 'Medium';
  if (event.attack_type === 'Port Scan') return event.action === 'BLOCKED' ? 'High' : 'Medium';
  return 'Low';
}

function inferProtocol(port) {
  const value = String(port || '');
  if (value.includes('53')) return 'UDP/TCP';
  if (value.includes('443')) return 'TCP/TLS';
  return 'TCP';
}


function buildAiModelMetrics() {
  return [
    { label: 'Model', value: 'RF v3', detail: 'ai_ips_model_v3.pkl, 2026-05-30 12:08 UTC 기준' },
    { label: '판정 일치율', value: '100%', detail: '900개 조합 비교 샘플 기준 900/900 동일 클래스' },
    { label: '확신도 기준', value: '70%', detail: '미만이면 신종/이상 트래픽 의심으로 보류' },
    { label: '주요 피처', value: '0.331', detail: 'special_char_count 중요도, login_fail_count 0.323' }
  ];
}

function buildAiSummary(event, severity) {
  const type = event.attack_type || 'Unknown';
  const signature = event.signature || '탐지 룰 정보 없음';
  const port = event.dest_port || '-';
  const action = event.action || 'ALERT';

  const profiles = {
    'Port Scan': {
      judgment: '다수 포트 접근 패턴을 기반으로 서비스 탐색 단계의 Port Scan으로 판단됩니다.',
      pattern: `Destination Port ${port}, 룰 "${signature}" 및 짧은 시간대 반복 접근 징후가 분류 근거입니다.`,
      intent: '공격 전 열려 있는 서비스와 취약한 진입점을 식별하려는 목적일 가능성이 큽니다.',
      response: 'Source IP의 최근 연결 횟수를 확인하고, 필요 시 IPS 차단 정책과 Wazuh 상관분석 룰을 강화합니다.'
    },
    'SQL Injection': {
      judgment: '웹 요청이 SQL Injection 시도로 분류된 고위험 애플리케이션 공격 이벤트입니다.',
      pattern: `룰 "${signature}"가 SQL 구문 삽입 패턴을 탐지했고 Destination Port ${port}로 웹 서비스 접근이 발생했습니다.`,
      intent: '인증 우회, 데이터베이스 정보 탈취, 데이터 변조를 노린 공격일 수 있습니다.',
      response: '웹 서버 접근 로그와 파라미터를 검토하고 WAF/애플리케이션 입력 검증 및 DB 계정 권한을 점검합니다.'
    },
    'Brute Force': {
      judgment: '반복 인증 시도 또는 로그인 실패 패턴에 기반한 Brute Force 이벤트입니다.',
      pattern: `룰 "${signature}"와 Destination Port ${port} 접근 패턴이 계정 탈취 시도와 일치합니다.`,
      intent: 'SSH 또는 웹 로그인 계정 탈취 후 내부 시스템 접근 권한을 확보하려는 목적일 수 있습니다.',
      response: '계정 잠금 정책, MFA, 실패 로그인 임계치를 확인하고 동일 Source IP의 연속 이벤트를 추적합니다.'
    }
  };

  const fallback = {
    judgment: `${type} 이벤트로 분류되었으며 추가 로그 상관분석이 필요합니다.`,
    pattern: `탐지 룰 "${signature}"와 Destination Port ${port} 값이 주요 분류 근거입니다.`,
    intent: '서비스 식별, 취약점 탐색 또는 권한 확보를 위한 사전 행위일 수 있습니다.',
    response: 'Source IP 평판, 동일 세션 이벤트, 대상 시스템 로그를 함께 확인합니다.'
  };

  const profile = profiles[type] || fallback;
  const decision = action === 'BLOCKED'
    ? `현재 IPS 정책에 의해 차단된 상태입니다. 위험도 ${severity} 이벤트로 관리자 사후 확인이 필요합니다.`
    : `자동 차단 전 상태입니다. 위험도 ${severity} 기준으로 관리자 확인 후 차단 여부를 결정해야 합니다.`;
  const confidencePolicy = 'v3 운영 로직은 predict_proba() 기준 최대 확신도 70% 미만을 공격으로 단정하지 않고 신종/이상 트래픽 의심으로 분류합니다.';

  return [
    { label: '공격 판단', value: profile.judgment },
    { label: '분류 근거', value: profile.pattern },
    { label: '예상 공격 목적', value: profile.intent },
    { label: '권장 대응 방법', value: profile.response },
    { label: 'AI 확신도 정책', value: confidencePolicy },
    { label: '차단/확인 상태', value: decision }
  ];
}

function TypePill({ type }) {
  const className = type === 'Port Scan'
    ? 'bg-cyan-400 text-slate-950'
    : type === 'Brute Force'
      ? 'bg-rose-400 text-slate-950'
      : type === 'SQL Injection'
        ? 'bg-purple-400 text-slate-950'
        : 'bg-slate-700 text-slate-100';
  return <span className={`rounded-full px-2 py-1 text-xs font-black ${className}`}>{type}</span>;
}

export default App;
