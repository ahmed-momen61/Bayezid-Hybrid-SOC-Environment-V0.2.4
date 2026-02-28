import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Shield, AlertTriangle, Activity, Terminal, Zap, X, 
  ChevronRight, Server, History, Play, LayoutDashboard, BarChart3 
} from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Radar, RadarChart, PolarGrid, PolarAngleAxis } from 'recharts';

const App = () => {
  const [activeTab, setActiveTab] = useState('dashboard'); // dashboard, simulator, history
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  
  const [simData, setSimData] = useState({
    source_ip: '192.168.1.50',
    event_type: 'Brute Force Attempt',
    payload_details: '',
    engine: 'LOCAL'
  });

  const fetchAlerts = async () => {
    try {
      const response = await axios.get('http://localhost:3000/api/alerts');
      setAlerts(response.data);
    } catch { console.error("Engine Offline"); }
  };

  const handleSimulate = async (e) => {
    e.preventDefault();
    try {
      await axios.post('http://localhost:3000/api/analyze', simData);
      setActiveTab('dashboard');
      fetchAlerts();
    } catch { alert("Simulation Failed"); }
  };

  useEffect(() => {
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex min-h-screen bg-[#0a0a0b] text-zinc-300 font-sans">
      
      {/* 1. Sidebar Navigation */}
      <nav className="w-64 border-r border-white/5 bg-[#0d0d0f] flex flex-col p-6 gap-8">
        <div className="flex items-center gap-3">
          <Shield className="text-emerald-500" size={28} />
          <span className="font-black text-white tracking-tighter text-xl italic">BAYEZID</span>
        </div>
        
        <div className="flex flex-col gap-2">
          <NavBtn active={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')} icon={<LayoutDashboard size={18}/>} label="Live Monitor" />
          <NavBtn active={activeTab === 'simulator'} onClick={() => setActiveTab('simulator')} icon={<Play size={18}/>} label="Simulate Attack" />
          <NavBtn active={activeTab === 'history'} onClick={() => setActiveTab('history')} icon={<History size={18}/>} label="Audit History" />
        </div>
      </nav>

      {/* 2. Main Content Area */}
      <main className="flex-1 overflow-y-auto p-8 custom-scrollbar">
        
        {/* --- Tab 1: Live Monitor --- */}
        {activeTab === 'dashboard' && (
          <div className="space-y-8 animate-in fade-in duration-500">
            <header className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white tracking-tight">Global Threat Surface</h2>
              <div className="flex items-center gap-4 text-[10px] font-mono bg-emerald-500/10 px-4 py-2 rounded-full border border-emerald-500/20 text-emerald-500">
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"/> ENGINES SYNCHRONIZED
              </div>
            </header>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <StatCard title="Total Analysis" value={alerts.length} icon={<Activity className="text-emerald-400"/>} />
              <StatCard title="Critical Hits" value={alerts.filter(a => a.severity === 'CRITICAL').length} icon={<AlertTriangle className="text-red-500"/>} />
              <StatCard title="AI Precision" value="99.8%" icon={<Zap className="text-yellow-500"/>} />
            </div>

            <div className="bg-[#121214] border border-white/5 rounded-2xl overflow-hidden shadow-2xl">
               <div className="p-4 bg-white/5 border-b border-white/5 flex items-center gap-2 text-xs font-bold tracking-widest uppercase">
                 <Terminal size={14}/> Recent Telemetry
               </div>
               <table className="w-full text-left text-xs">
                 <thead className="bg-black/20 text-zinc-500">
                   <tr>
                     <th className="p-4">Source Artifact</th>
                     <th className="p-4">Threat Type</th>
                     <th className="p-4">Priority</th>
                     <th className="p-4"></th>
                   </tr>
                 </thead>
                 <tbody className="divide-y divide-white/5">
                   {alerts.map(a => (
                     <tr key={a.id} onClick={() => setSelectedAlert(a)} className="hover:bg-white/[0.03] cursor-pointer group transition-all">
                       <td className="p-4 font-mono text-emerald-400">{a.sourceIp}</td>
                       <td className="p-4 font-medium text-white">{a.threatType}</td>
                       <td className="p-4">
                         <span className={`px-3 py-1 rounded-full text-[9px] font-bold border ${a.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 'bg-blue-500/10 text-blue-500 border-blue-500/20'}`}>
                           {a.severity}
                         </span>
                       </td>
                       <td className="p-4 text-right"><ChevronRight size={14} className="group-hover:translate-x-1 transition-transform"/></td>
                     </tr>
                   ))}
                 </tbody>
               </table>
            </div>
          </div>
        )}

        {}
        {activeTab === 'simulator' && (
          <div className="max-w-2xl mx-auto space-y-8 animate-in slide-in-from-bottom-4 duration-500">
            <h2 className="text-2xl font-bold text-white">Manual Threat Injection</h2>
            <form onSubmit={handleSimulate} className="bg-[#121214] border border-white/10 p-8 rounded-3xl space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <Input label="Source IP" value={simData.source_ip} onChange={e => setSimData({...simData, source_ip: e.target.value})} />
                <Select label="Selected Engine" value={simData.engine} onChange={e => setSimData({...simData, engine: e.target.value})} options={['LOCAL', 'CLOUD']} />
              </div>
              <Input label="Event Name" value={simData.event_type} onChange={e => setSimData({...simData, event_type: e.target.value})} />
              <div className="flex flex-col gap-2">
                <label className="text-[10px] uppercase font-bold text-zinc-500">Payload / Log Details</label>
                <textarea 
                  className="bg-black/40 border border-white/5 rounded-xl p-4 text-xs font-mono min-h-[150px] outline-none focus:border-emerald-500/50" 
                  placeholder="Paste raw NIDS or EDR logs here..."
                  value={simData.payload_details}
                  onChange={e => setSimData({...simData, payload_details: e.target.value})}
                />
              </div>
              <button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-4 rounded-xl transition-all shadow-lg shadow-emerald-500/10 flex items-center justify-center gap-2">
                <Play size={18}/> EXECUTE COGNITIVE ANALYSIS
              </button>
            </form>
          </div>
        )}

      </main>

      {}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/90 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-[#121214] border border-white/10 w-full max-w-5xl h-[85vh] rounded-3xl overflow-hidden flex flex-col modal-animate">
            
            <div className="p-6 border-b border-white/5 flex justify-between items-center bg-white/[0.02]">
              <div className="flex items-center gap-4">
                <BarChart3 className="text-emerald-500" />
                <h3 className="font-bold text-white uppercase tracking-[0.2em] text-sm">Forensic Intelligence Report</h3>
              </div>
              <button onClick={() => setSelectedAlert(null)} className="p-2 hover:bg-white/10 rounded-full transition-colors"><X size={24}/></button>
            </div>

            <div className="flex flex-1 overflow-hidden">
              {}
              <div className="w-1/3 border-r border-white/5 p-8 space-y-10 overflow-y-auto custom-scrollbar">
                
                <div className="space-y-4">
                   <h4 className="text-[10px] uppercase font-black text-zinc-500 tracking-widest">Confidence Metrics</h4>
                   <div className="h-48 flex items-center justify-center">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie data={[{v: 99.8}, {v: 0.2}]} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="v">
                            <Cell fill="#10b981" />
                            <Cell fill="#1f1f23" />
                          </Pie>
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="absolute flex flex-col items-center">
                        <span className="text-2xl font-black text-white">99%</span>
                        <span className="text-[8px] text-zinc-500 uppercase">Certainty</span>
                      </div>
                   </div>
                </div>

                <div className="space-y-4">
                  <h4 className="text-[10px] uppercase font-black text-zinc-500 tracking-widest">CVSS Severity Index</h4>
                  <div className="text-6xl font-black text-red-500 tracking-tighter">
                    {selectedAlert.cvssScore} <span className="text-xs text-zinc-600">/ 10.0</span>
                  </div>
                </div>

                <div className="p-4 bg-emerald-500/5 border border-emerald-500/10 rounded-2xl">
                  <p className="text-[10px] uppercase font-bold text-emerald-500 mb-1">Detection Logic</p>
                  <p className="text-xs font-mono text-zinc-400">{selectedAlert.engineUsed || 'Multi-Agent Hybrid'}</p>
                </div>
              </div>

              {}
              <div className="flex-1 p-10 overflow-y-auto custom-scrollbar space-y-10">
                <section className="space-y-4">
                  <h4 className="text-xs font-bold text-white flex items-center gap-2"><Activity size={16}/> Incident Narrative</h4>
                  <div className="bg-black/40 p-6 rounded-2xl border border-white/5 font-mono text-xs leading-relaxed text-zinc-400 shadow-inner italic">
                    {selectedAlert.detailedReport}
                  </div>
                </section>

                <section className="space-y-4">
                  <h4 className="text-xs font-bold text-white flex items-center gap-2"><Zap size={16} className="text-red-500"/> Remediation Steps</h4>
                  <div className="grid grid-cols-1 gap-3">
                    {selectedAlert.recommendedAction?.split('\n').map((step, idx) => (
                      <div key={idx} className="p-4 bg-white/[0.02] border border-white/5 rounded-xl text-xs flex gap-4 items-center">
                        <span className="w-6 h-6 rounded-lg bg-red-500/10 text-red-500 flex items-center justify-center font-bold">{idx+1}</span>
                        {step.replace(/^\d+\.\s*/, '')}
                      </div>
                    ))}
                  </div>
                </section>
              </div>
            </div>

          </div>
        </div>
      )}
    </div>
  );
};

const NavBtn = ({ active, onClick, icon, label }) => (
  <button onClick={onClick} className={`flex items-center gap-3 p-3 rounded-xl transition-all ${active ? 'bg-emerald-500/10 text-emerald-500 shadow-lg shadow-emerald-500/5' : 'text-zinc-500 hover:text-white hover:bg-white/5'}`}>
    {icon} <span className="text-xs font-bold uppercase tracking-wider">{label}</span>
  </button>
);

const StatCard = ({ title, value, icon }) => (
  <div className="bg-[#121214] border border-white/5 p-6 rounded-2xl shadow-xl">
    <div className="flex justify-between items-center mb-4">
      <span className="text-[10px] font-black uppercase tracking-widest text-zinc-500">{title}</span>
      {icon}
    </div>
    <div className="text-3xl font-black text-white tracking-tighter font-mono">{value}</div>
  </div>
);

const Input = ({ label, value, onChange }) => (
  <div className="flex flex-col gap-2">
    <label className="text-[10px] uppercase font-bold text-zinc-500">{label}</label>
    <input className="bg-black/40 border border-white/5 rounded-xl p-4 text-xs font-mono outline-none focus:border-emerald-500/50" value={value} onChange={onChange} />
  </div>
);

const Select = ({ label, value, onChange, options }) => (
  <div className="flex flex-col gap-2">
    <label className="text-[10px] uppercase font-bold text-zinc-500">{label}</label>
    <select className="bg-black/40 border border-white/5 rounded-xl p-4 text-xs font-mono outline-none appearance-none" value={value} onChange={onChange}>
      {options.map(opt => <option key={opt} value={opt}>{opt}</option>)}
    </select>
  </div>
);

export default App;