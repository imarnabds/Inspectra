import { useState, useMemo, useRef, useCallback } from 'react';
import './App.css';
import samplePackets from './data/samplePcap.json';
import { parsePcapArrayBuffer, type PacketData } from './utils/pcapParser';
import {
  Activity,
  Shield,
  Search,
  UploadCloud,
  RotateCcw,
  FileDown,
  Layers,
  ChevronRight,
  ChevronLeft,
  Copy,
  Check,
  AlertTriangle,
  Globe,
  Lock,
  Server,
  Hash,
  Database,
  Wifi,
  Terminal
} from 'lucide-react';

export default function App() {
  const [packets, setPackets] = useState<PacketData[]>(samplePackets as PacketData[]);
  const [activeFileName, setActiveFileName] = useState<string>('test_dpi.pcap');
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(4); // default to first TLS packet
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [selectedApp, setSelectedApp] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [isDragging, setIsDragging] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Compute summary analytics
  const analytics = useMemo(() => {
    let totalPayloadBytes = 0;
    let tcpCount = 0;
    let udpCount = 0;
    let anomalyCount = 0;
    const appMap: Record<string, number> = {};

    packets.forEach(p => {
      totalPayloadBytes += p.payloadLength || 0;
      if (p.hasTcp) tcpCount++;
      if (p.hasUdp) udpCount++;
      if (p.srcIp === '192.168.1.50') anomalyCount++;

      if (p.appType) {
        // Normalize app name if it's "DNS (App)"
        const name = p.appType.startsWith('DNS (') ? p.appType.replace('DNS (', '').replace(')', '') : p.appType;
        appMap[name] = (appMap[name] || 0) + 1;
      }
    });

    const sortedApps = Object.entries(appMap).sort((a, b) => b[1] - a[1]);

    return {
      totalPackets: packets.length,
      totalBytes: totalPayloadBytes,
      tcpCount,
      udpCount,
      anomalyCount,
      uniqueAppsCount: Object.keys(appMap).length,
      sortedApps
    };
  }, [packets]);

  // Filtered packets
  const filteredPackets = useMemo(() => {
    return packets.filter(p => {
      // Protocol filter
      if (protocolFilter === 'TLS' && !p.sni) return false;
      if (protocolFilter === 'HTTP' && !p.httpHost) return false;
      if (protocolFilter === 'DNS' && !p.dnsQuery) return false;
      if (protocolFilter === 'TCP' && !p.hasTcp) return false;
      if (protocolFilter === 'UDP' && !p.hasUdp) return false;
      if (protocolFilter === 'ANOMALY' && p.srcIp !== '192.168.1.50') return false;

      // App filter
      if (selectedApp) {
        if (!p.appType) return false;
        const normalized = p.appType.startsWith('DNS (') ? p.appType.replace('DNS (', '').replace(')', '') : p.appType;
        if (normalized !== selectedApp) return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesIp = p.srcIp.toLowerCase().includes(q) || p.destIp.toLowerCase().includes(q);
        const matchesPort = p.srcPort.toString().includes(q) || p.destPort.toString().includes(q);
        const matchesApp = p.appType?.toLowerCase().includes(q) || false;
        const matchesSni = p.sni?.toLowerCase().includes(q) || false;
        const matchesHost = p.httpHost?.toLowerCase().includes(q) || false;
        const matchesDns = p.dnsQuery?.toLowerCase().includes(q) || false;
        const matchesInfo = p.info.toLowerCase().includes(q);
        const matchesFlags = p.tcpFlags.toLowerCase().includes(q);
        return matchesIp || matchesPort || matchesApp || matchesSni || matchesHost || matchesDns || matchesInfo || matchesFlags;
      }

      return true;
    });
  }, [packets, protocolFilter, selectedApp, searchQuery]);

  // Selected packet
  const selectedPacket = useMemo(() => {
    if (!selectedPacketId) return filteredPackets[0] || null;
    return packets.find(p => p.id === selectedPacketId) || filteredPackets[0] || null;
  }, [packets, selectedPacketId, filteredPackets]);

  // Handle PCAP upload
  const handleFileUpload = useCallback((file: File) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const arrayBuffer = e.target?.result as ArrayBuffer;
        const parsed = parsePcapArrayBuffer(arrayBuffer);
        if (parsed.length === 0) {
          alert('No valid packets found in this PCAP file.');
          return;
        }
        setPackets(parsed);
        setActiveFileName(file.name);
        setSelectedPacketId(parsed[0]?.id || null);
        setProtocolFilter('ALL');
        setSelectedApp(null);
        setSearchQuery('');
      } catch (err: unknown) {
        alert('Failed to parse PCAP file: ' + (err instanceof Error ? err.message : String(err)));
      }
    };
    reader.readAsArrayBuffer(file);
  }, []);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const resetToSample = () => {
    setPackets(samplePackets as PacketData[]);
    setActiveFileName('test_dpi.pcap');
    setSelectedPacketId(4);
    setProtocolFilter('ALL');
    setSelectedApp(null);
    setSearchQuery('');
  };

  const exportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredPackets, null, 2));
    const dlAnchorElem = document.createElement('a');
    dlAnchorElem.setAttribute('href', dataStr);
    dlAnchorElem.setAttribute('download', `inspectra_export_${Date.now()}.json`);
    dlAnchorElem.click();
  };

  const exportCsv = () => {
    const headers = ['ID', 'Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Src Port', 'Dst Port', 'App Type', 'SNI', 'Host', 'DNS', 'Length'];
    const rows = filteredPackets.map(p => [
      p.id,
      p.timestamp,
      p.srcIp,
      p.destIp,
      p.protocol,
      p.srcPort || '',
      p.destPort || '',
      p.appType || '',
      p.sni || '',
      p.httpHost || '',
      p.dnsQuery || '',
      p.length
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `inspectra_export_${Date.now()}.csv`);
    link.click();
  };

  const copyHex = () => {
    if (!selectedPacket?.rawHex) return;
    navigator.clipboard.writeText(selectedPacket.rawHex);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const navigatePacket = (direction: 'prev' | 'next') => {
    if (!selectedPacket) return;
    const currentIndex = filteredPackets.findIndex(p => p.id === selectedPacket.id);
    if (currentIndex === -1) return;
    const nextIndex = direction === 'next' ? currentIndex + 1 : currentIndex - 1;
    if (nextIndex >= 0 && nextIndex < filteredPackets.length) {
      setSelectedPacketId(filteredPackets[nextIndex].id);
    }
  };

  return (
    <div 
      className="app-container"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <input 
        type="file" 
        ref={fileInputRef} 
        style={{ display: 'none' }} 
        accept=".pcap,.cap" 
        onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])} 
      />

      {/* Top Header */}
      <header className="app-header">
        <div className="brand-section">
          <div className="brand-icon-wrapper">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <h1 className="brand-title">
              Inspectra
              <span className="engine-tag">DPI v1.0</span>
            </h1>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              <span className="status-indicator"></span>
              <span>Inspectra Deep Packet Inspection Engine Active</span>
            </div>
          </div>
        </div>

        <div className="header-meta">
          <div className="active-file-pill" title="Inspectra In-Memory Capture Database">
            <Database size={15} style={{ color: 'var(--cyan-400)' }} />
            <span>Inspectra DB: <strong>{activeFileName}</strong></span>
            <span style={{ color: 'var(--text-muted)' }}>({packets.length} pkts)</span>
          </div>
        </div>

        <div className="header-actions">
          <button className="btn btn-outline" onClick={resetToSample} title="Reload default test_dpi.pcap dataset">
            <RotateCcw size={15} />
            <span>Reset Demo</span>
          </button>
          <button className="btn btn-secondary" onClick={() => fileInputRef.current?.click()}>
            <UploadCloud size={15} />
            <span>Upload PCAP</span>
          </button>
          <button className="btn btn-primary" onClick={exportJson} title="Export filtered packets to JSON">
            <FileDown size={15} />
            <span>Export JSON</span>
          </button>
          <button className="btn btn-secondary" onClick={exportCsv} title="Export filtered packets to CSV">
            <span>CSV</span>
          </button>
        </div>
      </header>

      {/* Drag & Drop Alert overlay */}
      {isDragging && (
        <div style={{
          padding: '1.25rem',
          borderRadius: '12px',
          border: '2px dashed var(--cyan-400)',
          background: 'rgba(0, 229, 255, 0.1)',
          color: 'var(--cyan-400)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '0.75rem',
          fontWeight: 600
        }}>
          <UploadCloud size={24} />
          <span>Drop your .pcap file anywhere to parse and inspect immediately!</span>
        </div>
      )}

      {/* KPI Cards Grid */}
      <section className="kpi-grid">
        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span>Total Captured</span>
            <Layers className="kpi-icon" />
          </div>
          <div className="kpi-value">{analytics.totalPackets}</div>
          <div className="kpi-footer">
            <span>Ethernet II framing decoded</span>
          </div>
        </div>

        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span>Payload Inspected</span>
            <Hash className="kpi-icon" />
          </div>
          <div className="kpi-value">
            {analytics.totalBytes > 1024 ? `${(analytics.totalBytes / 1024).toFixed(2)} KB` : `${analytics.totalBytes} B`}
          </div>
          <div className="kpi-footer">
            <span>Deep Layer-7 content</span>
          </div>
        </div>

        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span>Identified Services</span>
            <Shield className="kpi-icon" />
          </div>
          <div className="kpi-value">{analytics.uniqueAppsCount}</div>
          <div className="kpi-footer">
            <span>SNI, HTTP & DNS signatures</span>
          </div>
        </div>

        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span>Transport Split</span>
            <Server className="kpi-icon" />
          </div>
          <div className="kpi-value" style={{ fontSize: '1.45rem', marginTop: '0.2rem' }}>
            <span style={{ color: 'var(--blue-400)' }}>TCP {analytics.tcpCount}</span>
            <span style={{ color: 'var(--text-muted)', margin: '0 0.35rem' }}>/</span>
            <span style={{ color: 'var(--purple-400)' }}>UDP {analytics.udpCount}</span>
          </div>
          <div className="kpi-footer">
            <span>{((analytics.tcpCount / (analytics.totalPackets || 1)) * 100).toFixed(1)}% TCP ratio</span>
          </div>
        </div>

        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span>Security Alerts</span>
            <AlertTriangle className="kpi-icon" style={{ color: analytics.anomalyCount > 0 ? 'var(--rose-400)' : 'var(--text-muted)' }} />
          </div>
          <div className="kpi-value" style={{ color: analytics.anomalyCount > 0 ? 'var(--rose-400)' : 'var(--emerald-400)' }}>
            {analytics.anomalyCount}
          </div>
          <div className="kpi-footer">
            <span>{analytics.anomalyCount > 0 ? 'Simulated SYN flood (192.168.1.50)' : 'Traffic clean'}</span>
          </div>
        </div>
      </section>

      {/* Identified Applications Bar */}
      <section className="glass-panel apps-panel">
        <div className="apps-header">
          <div className="apps-title">
            <Globe size={15} style={{ color: 'var(--cyan-400)' }} />
            <span>Classified Applications & Protocols ({analytics.uniqueAppsCount})</span>
          </div>
          {selectedApp && (
            <button 
              className="copy-btn" 
              onClick={() => setSelectedApp(null)}
              style={{ color: 'var(--cyan-400)', borderColor: 'var(--cyan-400)' }}
            >
              Clear Filter: {selectedApp} ✕
            </button>
          )}
        </div>
        <div className="apps-list">
          {analytics.sortedApps.map(([app, count]) => {
            const isActive = selectedApp === app;
            return (
              <button
                key={app}
                className={`app-chip ${isActive ? 'active' : ''}`}
                onClick={() => setSelectedApp(isActive ? null : app)}
              >
                <span>{app}</span>
                <span className="app-count-badge">{count}</span>
              </button>
            );
          })}
        </div>
      </section>

      {/* Toolbar / Search & Filter Section */}
      <section className="toolbar-section">
        <div className="search-container">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            className="search-input"
            placeholder="Search by IP, port, SNI hostname, application, DNS domain, or payload..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="filter-pills">
          <button 
            className={`filter-pill ${protocolFilter === 'ALL' ? 'active' : ''}`}
            onClick={() => setProtocolFilter('ALL')}
          >
            All Packets ({packets.length})
          </button>
          <button 
            className={`filter-pill ${protocolFilter === 'TLS' ? 'active' : ''}`}
            onClick={() => setProtocolFilter('TLS')}
          >
            TLS / SNI
          </button>
          <button 
            className={`filter-pill ${protocolFilter === 'HTTP' ? 'active' : ''}`}
            onClick={() => setProtocolFilter('HTTP')}
          >
            HTTP
          </button>
          <button 
            className={`filter-pill ${protocolFilter === 'DNS' ? 'active' : ''}`}
            onClick={() => setProtocolFilter('DNS')}
          >
            DNS ({analytics.udpCount})
          </button>
          <button 
            className={`filter-pill ${protocolFilter === 'TCP' ? 'active' : ''}`}
            onClick={() => setProtocolFilter('TCP')}
          >
            TCP ({analytics.tcpCount})
          </button>
          <button 
            className={`filter-pill ${protocolFilter === 'UDP' ? 'active' : ''}`}
            onClick={() => setProtocolFilter('UDP')}
          >
            UDP ({analytics.udpCount})
          </button>
          <button 
            className={`filter-pill ${protocolFilter === 'ANOMALY' ? 'active' : ''}`}
            onClick={() => setProtocolFilter('ANOMALY')}
            style={protocolFilter === 'ANOMALY' ? { borderColor: 'var(--rose-400)', color: 'var(--rose-400)' } : {}}
          >
            Anomalous / Blocked ({analytics.anomalyCount})
          </button>
        </div>
      </section>

      {/* Main Workspace (Table + Inspector) */}
      <main className="workspace-grid">
        {/* Packet Table Panel */}
        <div className="glass-panel table-panel">
          <div className="table-scroll-container">
            {filteredPackets.length === 0 ? (
              <div className="empty-state">
                <Search className="empty-icon" />
                <h3>No packets match current filter</h3>
                <p>Try resetting the search query or switching protocol filters.</p>
                <button className="btn btn-outline" onClick={() => { setSearchQuery(''); setProtocolFilter('ALL'); setSelectedApp(null); }}>
                  Reset All Filters
                </button>
              </div>
            ) : (
              <table className="packet-table">
                <thead>
                  <tr>
                    <th style={{ width: '45px' }}>#</th>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Length</th>
                    <th>DPI Service</th>
                    <th>Summary Info</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredPackets.map(pkt => {
                    const isSelected = selectedPacket?.id === pkt.id;
                    const isAnomaly = pkt.srcIp === '192.168.1.50';

                    let badgeClass = 'badge-tcp';
                    if (pkt.sni) badgeClass = 'badge-tls';
                    else if (pkt.httpHost) badgeClass = 'badge-http';
                    else if (pkt.dnsQuery) badgeClass = 'badge-dns';
                    else if (pkt.hasUdp) badgeClass = 'badge-udp';

                    return (
                      <tr
                        key={pkt.id}
                        className={`packet-row ${isSelected ? 'selected' : ''} ${isAnomaly ? 'anomaly' : ''}`}
                        onClick={() => setSelectedPacketId(pkt.id)}
                      >
                        <td className="mono-text" style={{ color: 'var(--text-muted)' }}>{pkt.id}</td>
                        <td className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                          {pkt.timestamp.split(' ')[1] || pkt.timestamp}
                        </td>
                        <td className="mono-text">
                          {pkt.srcIp ? `${pkt.srcIp}${pkt.srcPort ? `:${pkt.srcPort}` : ''}` : pkt.srcMac}
                        </td>
                        <td className="mono-text">
                          {pkt.destIp ? `${pkt.destIp}${pkt.destPort ? `:${pkt.destPort}` : ''}` : pkt.destMac}
                        </td>
                        <td>
                          <span className={`badge ${badgeClass}`}>
                            {pkt.sni ? 'TLS' : pkt.httpHost ? 'HTTP' : pkt.dnsQuery ? 'DNS' : pkt.protocol}
                          </span>
                        </td>
                        <td className="mono-text" style={{ color: 'var(--text-muted)' }}>{pkt.length} B</td>
                        <td>
                          {pkt.appType ? (
                            <span style={{ 
                              color: isAnomaly ? 'var(--rose-400)' : 'var(--cyan-400)', 
                              fontWeight: 600,
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.3rem'
                            }}>
                              {pkt.sni && <Lock size={12} />}
                              {pkt.httpHost && <Globe size={12} />}
                              {pkt.dnsQuery && <Wifi size={12} />}
                              {pkt.appType}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>—</span>
                          )}
                        </td>
                        <td style={{ color: isAnomaly ? 'var(--rose-400)' : 'var(--text-secondary)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {pkt.info || `${pkt.protocol} packet`}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Deep Packet Inspector Panel */}
        <aside className="glass-panel inspector-panel">
          {selectedPacket ? (
            <>
              <div className="inspector-header">
                <div className="inspector-title">
                  <Shield size={18} style={{ color: 'var(--cyan-400)' }} />
                  <span>Packet #{selectedPacket.id} Inspector</span>
                </div>
                <div style={{ display: 'flex', gap: '0.4rem' }}>
                  <button 
                    className="copy-btn" 
                    onClick={() => navigatePacket('prev')} 
                    title="Previous Packet"
                  >
                    <ChevronLeft size={14} />
                  </button>
                  <button 
                    className="copy-btn" 
                    onClick={() => navigatePacket('next')} 
                    title="Next Packet"
                  >
                    <ChevronRight size={14} />
                  </button>
                </div>
              </div>

              {/* Layer 7 Deep Packet Inspection (DPI) */}
              {(selectedPacket.appType || selectedPacket.sni || selectedPacket.httpHost || selectedPacket.dnsQuery) && (
                <div className="layer-card highlight">
                  <div className="layer-card-header">
                    <span style={{ color: 'var(--cyan-400)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <Activity size={15} />
                      Deep Packet Inspection (Layer 7)
                    </span>
                    <span className="badge badge-tls">IDENTIFIED</span>
                  </div>
                  <div className="layer-content">
                    {selectedPacket.appType && (
                      <div className="prop-row">
                        <span className="prop-label">Service Application:</span>
                        <span className="prop-val highlight" style={{ fontWeight: 700 }}>
                          {selectedPacket.appType}
                        </span>
                      </div>
                    )}
                    {selectedPacket.sni && (
                      <div className="prop-row">
                        <span className="prop-label">TLS SNI Hostname:</span>
                        <span className="prop-val highlight">{selectedPacket.sni}</span>
                      </div>
                    )}
                    {selectedPacket.httpHost && (
                      <div className="prop-row">
                        <span className="prop-label">HTTP Host:</span>
                        <span className="prop-val highlight">{selectedPacket.httpHost}</span>
                      </div>
                    )}
                    {selectedPacket.dnsQuery && (
                      <div className="prop-row">
                        <span className="prop-label">DNS Query Domain:</span>
                        <span className="prop-val highlight">{selectedPacket.dnsQuery}</span>
                      </div>
                    )}
                    <div className="prop-row">
                      <span className="prop-label">Inspection Status:</span>
                      <span className="prop-val" style={{ color: 'var(--emerald-400)' }}>Decoded Signature Match</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Layer 4: Transport Layer */}
              <div className="layer-card">
                <div className="layer-card-header">
                  <span>
                    {selectedPacket.hasTcp ? 'Transmission Control Protocol (TCP)' : selectedPacket.hasUdp ? 'User Datagram Protocol (UDP)' : 'Transport Layer'}
                  </span>
                  <span className="mono-text" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    {selectedPacket.srcPort} → {selectedPacket.destPort}
                  </span>
                </div>
                <div className="layer-content">
                  <div className="prop-row">
                    <span className="prop-label">Source Port:</span>
                    <span className="prop-val">{selectedPacket.srcPort}</span>
                  </div>
                  <div className="prop-row">
                    <span className="prop-label">Destination Port:</span>
                    <span className="prop-val">{selectedPacket.destPort}</span>
                  </div>
                  {selectedPacket.hasTcp && (
                    <>
                      <div className="prop-row">
                        <span className="prop-label">Flags:</span>
                        <span className="prop-val highlight">{selectedPacket.tcpFlags || 'None'}</span>
                      </div>
                      <div className="prop-row">
                        <span className="prop-label">Sequence Number:</span>
                        <span className="prop-val">{selectedPacket.seqNumber}</span>
                      </div>
                      <div className="prop-row">
                        <span className="prop-label">Acknowledgment:</span>
                        <span className="prop-val">{selectedPacket.ackNumber}</span>
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* Layer 3: Network Layer */}
              {selectedPacket.hasIp && (
                <div className="layer-card">
                  <div className="layer-card-header">
                    <span>Internet Protocol Version {selectedPacket.ipVersion || 4}</span>
                    <span className="mono-text" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                      TTL={selectedPacket.ttl}
                    </span>
                  </div>
                  <div className="layer-content">
                    <div className="prop-row">
                      <span className="prop-label">Source Address:</span>
                      <span className="prop-val" style={selectedPacket.srcIp === '192.168.1.50' ? { color: 'var(--rose-400)' } : {}}>
                        {selectedPacket.srcIp}
                        {selectedPacket.srcIp === '192.168.1.50' && ' (Anomaly Source)'}
                      </span>
                    </div>
                    <div className="prop-row">
                      <span className="prop-label">Destination Address:</span>
                      <span className="prop-val">{selectedPacket.destIp}</span>
                    </div>
                    <div className="prop-row">
                      <span className="prop-label">Protocol:</span>
                      <span className="prop-val">{selectedPacket.protocol}</span>
                    </div>
                    <div className="prop-row">
                      <span className="prop-label">Time to Live (TTL):</span>
                      <span className="prop-val">{selectedPacket.ttl} hops</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Layer 2: Link Layer */}
              <div className="layer-card">
                <div className="layer-card-header">
                  <span>Ethernet II Framing</span>
                  <span className="mono-text" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    {selectedPacket.etherType}
                  </span>
                </div>
                <div className="layer-content">
                  <div className="prop-row">
                    <span className="prop-label">Source MAC:</span>
                    <span className="prop-val">{selectedPacket.srcMac}</span>
                  </div>
                  <div className="prop-row">
                    <span className="prop-label">Destination MAC:</span>
                    <span className="prop-val">{selectedPacket.destMac}</span>
                  </div>
                  <div className="prop-row">
                    <span className="prop-label">EtherType:</span>
                    <span className="prop-val">{selectedPacket.etherType} (IPv4)</span>
                  </div>
                </div>
              </div>

              {/* Payload Hex / ASCII Inspector */}
              <div className="layer-card">
                <div className="layer-card-header">
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <Terminal size={14} />
                    Payload Byte Stream ({selectedPacket.payloadLength} Bytes)
                  </span>
                  <button className="copy-btn" onClick={copyHex} title="Copy raw hex">
                    {copied ? <Check size={12} color="var(--emerald-400)" /> : <Copy size={12} />}
                    <span>{copied ? 'Copied' : 'Copy Hex'}</span>
                  </button>
                </div>
                <div className="layer-content" style={{ padding: '0.65rem' }}>
                  {selectedPacket.hexDump ? (
                    <div className="hexdump-container">
                      {selectedPacket.hexDump}
                    </div>
                  ) : (
                    <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                      No payload in this packet (Control / Handshake frame)
                    </div>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state">
              <Shield className="empty-icon" />
              <h3>Select a packet to inspect</h3>
              <p>Click on any row in the packet table to view protocol layers and byte dumps.</p>
            </div>
          )}
        </aside>
      </main>
    </div>
  );
}
