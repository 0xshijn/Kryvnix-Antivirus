import { useEffect, useState } from 'react';

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8080/api/v1';

interface Device {
  deviceId: string; hostname: string; osVersion: string; agentVersion: string;
  dbVersion: string; realtimeEnabled: boolean; status: string; lastHeartbeat: string;
}
interface Signature {
  id: number; sha256: string; threatName: string; category: string; severity: string; addedAt: string;
}
interface YaraRule {
  id: number; ruleName: string; category: string; severity: string; ruleSource: string; enabled: boolean;
}
interface Detection {
  id: string; deviceId: string; fileName: string; threatName: string; category: string;
  severity: string; detectionMethod: string; actionTaken: string; detectedAt: string;
}
interface AuditLog {
  id: number; actor: string; action: string; details: string; createdAt: string;
}

type Tab = 'overview' | 'endpoints' | 'signatures' | 'yara' | 'audit';

export default function App() {
  const [tab, setTab] = useState<Tab>('overview');
  const [apiOnline, setApiOnline] = useState(false);
  const [toast, setToast] = useState('');
  const [devices, setDevices] = useState<Device[]>([]);
  const [signatures, setSignatures] = useState<Signature[]>([]);
  const [yaraRules, setYaraRules] = useState<YaraRule[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [audits, setAudits] = useState<AuditLog[]>([]);

  const [newSha, setNewSha] = useState('');
  const [newThreat, setNewThreat] = useState('');
  const [newCat, setNewCat] = useState('Trojan');
  const [newSev, setNewSev] = useState('High');

  const [yaraName, setYaraName] = useState('');
  const [yaraSource, setYaraSource] = useState('rule Custom_Malware { strings: $a = "SUSPICIOUS" condition: $a }');

  const notify = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(''), 4000);
  };

  const loadAll = async () => {
    try {
      const [d, s, y, det, au] = await Promise.all([
        fetch(`${API_BASE}/devices`).then(r => r.json()),
        fetch(`${API_BASE}/signatures`).then(r => r.json()),
        fetch(`${API_BASE}/yara`).then(r => r.json()),
        fetch(`${API_BASE}/detections`).then(r => r.json()),
        fetch(`${API_BASE}/audit`).then(r => r.json()),
      ]);
      setDevices(d); setSignatures(s); setYaraRules(y); setDetections(det); setAudits(au);
      setApiOnline(true);
    } catch {
      setApiOnline(false);
      // Graceful demo preview data when Backend API isn't started yet
      if (devices.length === 0) {
        setDevices([
          { deviceId: 'KRV-DESKTOP-MAIN', hostname: 'WORKSTATION-01', osVersion: 'Windows 11 Pro', agentVersion: '2.0.0', dbVersion: 'v2026.11.25', realtimeEnabled: true, status: 'Protected', lastHeartbeat: new Date().toISOString() },
          { deviceId: 'KRV-FINANCE-02', hostname: 'FINANCE-PC-02', osVersion: 'Windows 11 Enterprise', agentVersion: '2.0.0', dbVersion: 'v2026.11.25', realtimeEnabled: true, status: 'Protected', lastHeartbeat: new Date().toISOString() },
          { deviceId: 'KRV-LAB-03', hostname: 'MALWARE-LAB-03', osVersion: 'Windows 10 Pro', agentVersion: '2.0.0', dbVersion: 'v2025.01.15', realtimeEnabled: false, status: 'Attention', lastHeartbeat: new Date().toISOString() },
        ]);
        setSignatures([
          { id: 1, sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', threatName: 'EICAR-Test-File', category: 'Trojan', severity: 'High', addedAt: new Date().toISOString() },
          { id: 2, sha256: 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa', threatName: 'Ransom.Win32.WannaCry.Gen', category: 'Ransomware', severity: 'Critical', addedAt: new Date().toISOString() },
        ]);
        setYaraRules([
          { id: 1, ruleName: 'Kryvnix_Ransomware_Note', category: 'Ransomware', severity: 'Critical', ruleSource: 'rule Kryvnix_Ransomware_Note { strings: $a = "YOUR FILES HAVE BEEN ENCRYPTED" condition: $a }', enabled: true },
        ]);
        setDetections([
          { id: '1', deviceId: 'KRV-DESKTOP-MAIN', fileName: 'eicar.com', threatName: 'EICAR-Test-File', category: 'Trojan', severity: 'High', detectionMethod: 'SHA-256 Signature', actionTaken: 'Quarantined', detectedAt: new Date().toISOString() },
        ]);
      }
    }
  };

  useEffect(() => { void loadAll(); }, []);

  const triggerRemoteScan = async (deviceId: string) => {
    try {
      const res = await fetch(`${API_BASE}/devices/${deviceId}/remote-scan`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'Quick' })
      });
      if (res.ok) notify(`Đã gửi lệnh Quét nhanh từ xa tới ${deviceId}`);
      await loadAll();
    } catch {
      notify('Cần khởi động Backend API (localhost:8080) để gửi lệnh từ xa.');
    }
  };

  const addSignature = async () => {
    if (!newSha.trim() || !newThreat.trim()) return;
    try {
      await fetch(`${API_BASE}/signatures`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sha256: newSha, threatName: newThreat, category: newCat, severity: newSev })
      });
      setNewSha(''); setNewThreat('');
      notify('Đã thêm chữ ký mã độc mới vào CSDL trung tâm.');
      await loadAll();
    } catch {
      notify('Backend API ngoại tuyến — khởi chạy KryvnixAntivirus.Api trên cổng 8080.');
    }
  };

  const deleteSignature = async (id: number) => {
    try {
      await fetch(`${API_BASE}/signatures/${id}`, { method: 'DELETE' });
      await loadAll();
    } catch { /* ignore */ }
  };

  const addYara = async () => {
    if (!yaraName.trim() || !yaraSource.trim()) return;
    try {
      await fetch(`${API_BASE}/yara`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ruleName: yaraName, category: newCat, severity: newSev, ruleSource: yaraSource })
      });
      setYaraName('');
      notify('Đã thêm quy tắc YARA mới.');
      await loadAll();
    } catch {
      notify('Backend API ngoại tuyến.');
    }
  };

  const toggleYara = async (id: number) => {
    try {
      await fetch(`${API_BASE}/yara/${id}/toggle`, { method: 'PATCH' });
      await loadAll();
    } catch { /* ignore */ }
  };

  const exportReport = () => {
    const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), devices, detections, signatures, yaraRules }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'kryvnix-fleet-report.json'; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-shield">K</div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 16 }}>Kryvnix Console</div>
            <div style={{ fontSize: 11, color: '#64748b' }}>Enterprise Admin v2.0</div>
          </div>
        </div>
        <button className={`nav-btn ${tab === 'overview' ? 'active' : ''}`} onClick={() => setTab('overview')}>Tổng quan hệ thống</button>
        <button className={`nav-btn ${tab === 'endpoints' ? 'active' : ''}`} onClick={() => setTab('endpoints')}>Quản lý máy trạm</button>
        <button className={`nav-btn ${tab === 'signatures' ? 'active' : ''}`} onClick={() => setTab('signatures')}>CSDL Chữ ký SHA-256</button>
        <button className={`nav-btn ${tab === 'yara' ? 'active' : ''}`} onClick={() => setTab('yara')}>Quản lý luật YARA</button>
        <button className={`nav-btn ${tab === 'audit' ? 'active' : ''}`} onClick={() => setTab('audit')}>Nhật ký kiểm toán</button>
        <div style={{ marginTop: 'auto', padding: 12, borderRadius: 12, background: '#112228', border: '1px solid #1e3d36', fontSize: 12 }}>
          <div style={{ fontWeight: 600 }}>Backend API (8080)</div>
          <div style={{ color: apiOnline ? '#4ade80' : '#fbbf24', marginTop: 4 }}>
            {apiOnline ? '● Đang kết nối trực tiếp' : '● Chế độ xem trước ngoại tuyến'}
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="header">
          <div>
            <h1 style={{ fontSize: 22 }}>Kryvnix Antivirus — Central Security Dashboard</h1>
            <p style={{ color: '#94a3b8', fontSize: 13, marginTop: 3 }}>Giám sát đa thiết bị, quản trị chữ ký Ed25519, luật YARA & điều khiển quét từ xa</p>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <button className="btn" onClick={() => void loadAll()}>Làm mới dữ liệu</button>
            <button className="btn btn-primary" onClick={exportReport}>Xuất báo cáo JSON</button>
          </div>
        </div>

        {toast && (
          <div style={{ marginBottom: 14, padding: '10px 14px', borderRadius: 10, background: '#133628', border: '1px solid #22c55e', color: '#86efac', fontSize: 13 }}>
            {toast}
          </div>
        )}

        {tab === 'overview' && (
          <>
            <div className="grid-4">
              <div className="card">
                <div style={{ color: '#94a3b8', fontSize: 12.5 }}>Máy trạm đang quản lý</div>
                <div className="stat-value" style={{ color: '#38bdf8' }}>{devices.length}</div>
              </div>
              <div className="card">
                <div style={{ color: '#94a3b8', fontSize: 12.5 }}>Mối đe dọa báo cáo</div>
                <div className="stat-value" style={{ color: '#f87171' }}>{detections.length}</div>
              </div>
              <div className="card">
                <div style={{ color: '#94a3b8', fontSize: 12.5 }}>Chữ ký SHA-256 trung tâm</div>
                <div className="stat-value" style={{ color: '#4ade80' }}>{signatures.length}</div>
              </div>
              <div className="card">
                <div style={{ color: '#94a3b8', fontSize: 12.5 }}>Quy tắc YARA hoạt động</div>
                <div className="stat-value" style={{ color: '#fbbf24' }}>{yaraRules.filter(y => y.enabled).length}</div>
              </div>
            </div>

            <div className="card">
              <h3 style={{ fontSize: 16 }}>Cảnh báo phát hiện mã độc gần đây</h3>
              <table>
                <thead>
                  <tr><th>Thiết bị</th><th>Tệp tin</th><th>Mối đe dọa</th><th>Phương thức</th><th>Hành động</th></tr>
                </thead>
                <tbody>
                  {detections.map(d => (
                    <tr key={d.id}>
                      <td>{d.deviceId}</td>
                      <td>{d.fileName}</td>
                      <td><span className="badge badge-red">{d.threatName}</span></td>
                      <td><span className="badge badge-blue">{d.detectionMethod}</span></td>
                      <td><span className="badge badge-green">{d.actionTaken}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        {tab === 'endpoints' && (
          <div className="card">
            <h3 style={{ fontSize: 16 }}>Danh sách thiết bị Windows Endpoint</h3>
            <table>
              <thead>
                <tr><th>Device ID</th><th>Hostname</th><th>Hệ điều hành</th><th>CSDL</th><th>Trạng thái</th><th>Điều khiển</th></tr>
              </thead>
              <tbody>
                {devices.map(dev => (
                  <tr key={dev.deviceId}>
                    <td style={{ fontFamily: 'Consolas, monospace' }}>{dev.deviceId}</td>
                    <td>{dev.hostname}</td>
                    <td>{dev.osVersion}</td>
                    <td>{dev.dbVersion}</td>
                    <td><span className={`badge ${dev.realtimeEnabled ? 'badge-green' : 'badge-amber'}`}>{dev.status}</span></td>
                    <td><button className="btn btn-primary" onClick={() => void triggerRemoteScan(dev.deviceId)}>Quét từ xa</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'signatures' && (
          <div className="card">
            <h3 style={{ fontSize: 16, marginBottom: 12 }}>Quản lý CSDL chữ ký mã độc (SHA-256)</h3>
            <div className="form-row">
              <input className="input" placeholder="SHA-256 (64 ký tự hex)" value={newSha} onChange={e => setNewSha(e.target.value)} />
              <input className="input" placeholder="Tên mối đe dọa (vd: Trojan.Win64.Test)" value={newThreat} onChange={e => setNewThreat(e.target.value)} />
              <select className="input" value={newCat} onChange={e => setNewCat(e.target.value)}>
                <option>Trojan</option><option>Ransomware</option><option>Spyware</option><option>Worm</option><option>Backdoor</option><option>Adware</option>
              </select>
              <select className="input" value={newSev} onChange={e => setNewSev(e.target.value)}>
                <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
              </select>
              <button className="btn btn-primary" onClick={() => void addSignature()}>+ Thêm</button>
            </div>
            <table>
              <thead><tr><th>Tên mã độc</th><th>Loại</th><th>Mức độ</th><th>SHA-256</th><th></th></tr></thead>
              <tbody>
                {signatures.map(s => (
                  <tr key={s.id}>
                    <td>{s.threatName}</td>
                    <td>{s.category}</td>
                    <td><span className="badge badge-red">{s.severity}</span></td>
                    <td style={{ fontFamily: 'Consolas, monospace', fontSize: 12 }}>{s.sha256.slice(0, 28)}...</td>
                    <td><button className="btn btn-danger" onClick={() => void deleteSignature(s.id)}>Xóa</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'yara' && (
          <div className="card">
            <h3 style={{ fontSize: 16, marginBottom: 12 }}>Quản lý quy tắc YARA</h3>
            <div style={{ display: 'grid', gap: 10, marginBottom: 16 }}>
              <input className="input" placeholder="Tên quy tắc YARA (vd: Kryvnix_Stealer_Strings)" value={yaraName} onChange={e => setYaraName(e.target.value)} />
              <textarea className="input" rows={3} value={yaraSource} onChange={e => setYaraSource(e.target.value)} style={{ fontFamily: 'Consolas, monospace' }} />
              <div><button className="btn btn-primary" onClick={() => void addYara()}>+ Thêm luật YARA</button></div>
            </div>
            <table>
              <thead><tr><th>Quy tắc</th><th>Loại</th><th>Trạng thái</th><th>Thao tác</th></tr></thead>
              <tbody>
                {yaraRules.map(r => (
                  <tr key={r.id}>
                    <td style={{ fontWeight: 600 }}>{r.ruleName}</td>
                    <td>{r.category}</td>
                    <td><span className={`badge ${r.enabled ? 'badge-green' : 'badge-amber'}`}>{r.enabled ? 'Đang bật' : 'Tạm tắt'}</span></td>
                    <td><button className="btn" onClick={() => void toggleYara(r.id)}>Bật / Tắt</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'audit' && (
          <div className="card">
            <h3 style={{ fontSize: 16 }}>Nhật ký kiểm toán (Audit Logs)</h3>
            <table>
              <thead><tr><th>Tác nhân</th><th>Hành động</th><th>Chi tiết</th><th>Thời gian</th></tr></thead>
              <tbody>
                {audits.map(a => (
                  <tr key={a.id}>
                    <td>{a.actor}</td>
                    <td><span className="badge badge-blue">{a.action}</span></td>
                    <td>{a.details}</td>
                    <td style={{ color: '#94a3b8' }}>{new Date(a.createdAt).toLocaleString('vi-VN')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </main>
    </div>
  );
}
