/**
 * Inspectra PCAP Dissector Engine
 * Browser-side binary PCAP parser decoding L2 Ethernet, L3 IPv4, L4 TCP/UDP, and L7 DPI metadata.
 */
export interface PacketData {
  id: number;
  timestamp: string;
  timestampSec: number;
  timestampUsec: number;
  length: number;
  srcMac: string;
  destMac: string;
  etherType: string;
  hasIp: boolean;
  ipVersion?: number;
  srcIp: string;
  destIp: string;
  protocol: string;
  ttl: number;
  hasTcp: boolean;
  hasUdp: boolean;
  srcPort: number;
  destPort: number;
  tcpFlags: string;
  seqNumber: number;
  ackNumber: number;
  appType: string | null;
  sni: string | null;
  httpHost: string | null;
  dnsQuery: string | null;
  info: string;
  payloadLength: number;
  hexDump: string;
  rawHex: string;
}

export function parsePcapArrayBuffer(buffer: ArrayBuffer): PacketData[] {
  if (buffer.byteLength < 24) {
    throw new Error('File too small to be a valid PCAP capture (minimum 24 bytes).');
  }

  const view = new DataView(buffer);
  const magic = view.getUint32(0, true);
  let littleEndian = true;

  if (magic === 0xa1b2c3d4) {
    littleEndian = true;
  } else if (magic === 0xd4c3b2a1) {
    littleEndian = false;
  } else {
    // Try big endian read
    const magicBE = view.getUint32(0, false);
    if (magicBE === 0xa1b2c3d4) {
      littleEndian = false;
    } else {
      throw new Error(`Invalid PCAP magic number (0x${magic.toString(16)}). Only standard .pcap format is supported.`);
    }
  }

  const packets: PacketData[] = [];
  let offset = 24;
  let packetId = 1;
  const bytes = new Uint8Array(buffer);

  while (offset + 16 <= buffer.byteLength) {
    const tsSec = view.getUint32(offset, littleEndian);
    const tsUsec = view.getUint32(offset + 4, littleEndian);
    const inclLen = view.getUint32(offset + 8, littleEndian);
    offset += 16;

    if (offset + inclLen > buffer.byteLength) {
      break;
    }

    const packetBytes = bytes.subarray(offset, offset + inclLen);
    offset += inclLen;

    const parsed = parseSinglePacket(packetBytes, packetId++, tsSec, tsUsec, inclLen);
    packets.push(parsed);
  }

  return packets;
}

function parseSinglePacket(
  data: Uint8Array,
  id: number,
  tsSec: number,
  tsUsec: number,
  length: number
): PacketData {
  const date = new Date(tsSec * 1000);
  const timeStr = `${date.toISOString().replace('T', ' ').replace('Z', '')}.${tsUsec.toString().padStart(6, '0')}`;

  const pkt: PacketData = {
    id,
    timestamp: timeStr,
    timestampSec: tsSec,
    timestampUsec: tsUsec,
    length,
    srcMac: '',
    destMac: '',
    etherType: '0x0000',
    hasIp: false,
    srcIp: '',
    destIp: '',
    protocol: 'Unknown',
    ttl: 0,
    hasTcp: false,
    hasUdp: false,
    srcPort: 0,
    destPort: 0,
    tcpFlags: '',
    seqNumber: 0,
    ackNumber: 0,
    appType: null,
    sni: null,
    httpHost: null,
    dnsQuery: null,
    info: '',
    payloadLength: 0,
    hexDump: '',
    rawHex: Array.from(data).map(b => b.toString(16).padStart(2, '0')).join('')
  };

  if (data.length < 14) return pkt;

  // Ethernet L2
  pkt.destMac = Array.from(data.subarray(0, 6)).map(b => b.toString(16).padStart(2, '0')).join(':');
  pkt.srcMac = Array.from(data.subarray(6, 12)).map(b => b.toString(16).padStart(2, '0')).join(':');
  const etherType = (data[12] << 8) | data[13];
  pkt.etherType = `0x${etherType.toString(16).padStart(4, '0')}`;

  let offset = 14;

  // IPv4 L3
  if (etherType === 0x0800 && data.length >= offset + 20) {
    const vIhl = data[offset];
    const ihl = (vIhl & 0x0F) * 4;
    pkt.hasIp = true;
    pkt.ipVersion = (vIhl >> 4) & 0x0F;
    pkt.ttl = data[offset + 8];
    const protoNum = data[offset + 9];
    pkt.srcIp = `${data[offset + 12]}.${data[offset + 13]}.${data[offset + 14]}.${data[offset + 15]}`;
    pkt.destIp = `${data[offset + 16]}.${data[offset + 17]}.${data[offset + 18]}.${data[offset + 19]}`;

    if (protoNum === 6) pkt.protocol = 'TCP';
    else if (protoNum === 17) pkt.protocol = 'UDP';
    else if (protoNum === 1) pkt.protocol = 'ICMP';
    else pkt.protocol = `Proto-${protoNum}`;

    offset += ihl;

    // TCP L4
    if (protoNum === 6 && data.length >= offset + 20) {
      pkt.hasTcp = true;
      pkt.srcPort = (data[offset] << 8) | data[offset + 1];
      pkt.destPort = (data[offset + 2] << 8) | data[offset + 3];
      pkt.seqNumber = ((data[offset + 4] << 24) >>> 0) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7];
      pkt.ackNumber = ((data[offset + 8] << 24) >>> 0) | (data[offset + 9] << 16) | (data[offset + 10] << 8) | data[offset + 11];

      const dataOffset = (data[offset + 12] >> 4) * 4;
      const flags = data[offset + 13];
      const flagList: string[] = [];
      if (flags & 0x02) flagList.push('SYN');
      if (flags & 0x10) flagList.push('ACK');
      if (flags & 0x01) flagList.push('FIN');
      if (flags & 0x04) flagList.push('RST');
      if (flags & 0x08) flagList.push('PSH');
      if (flags & 0x20) flagList.push('URG');
      pkt.tcpFlags = flagList.join(' ');
      pkt.info = `${pkt.srcPort} → ${pkt.destPort} [${pkt.tcpFlags || 'none'}] Seq=${pkt.seqNumber}`;

      offset += dataOffset;
    } else if (protoNum === 17 && data.length >= offset + 8) {
      // UDP L4
      pkt.hasUdp = true;
      pkt.srcPort = (data[offset] << 8) | data[offset + 1];
      pkt.destPort = (data[offset + 2] << 8) | data[offset + 3];
      const udpLen = (data[offset + 4] << 8) | data[offset + 5];
      pkt.info = `${pkt.srcPort} → ${pkt.destPort} Len=${Math.max(0, udpLen - 8)}`;
      offset += 8;
    }
  }

  // Payload L7
  if (offset < data.length) {
    const payload = data.subarray(offset);
    pkt.payloadLength = payload.length;

    // Hex dump
    const lines: string[] = [];
    for (let i = 0; i < payload.length; i += 16) {
      const slice = payload.subarray(i, i + 16);
      const hexPart = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(48, ' ');
      const asciiPart = Array.from(slice).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
      lines.push(`${i.toString(16).padStart(4, '0')}   ${hexPart}   ${asciiPart}`);
    }
    pkt.hexDump = lines.join('\n');

    // DPI: TLS Client Hello SNI
    if (pkt.hasTcp && payload.length >= 9 && payload[0] === 0x16 && payload[5] === 0x01) {
      const sni = extractTlsSni(payload);
      if (sni) {
        pkt.sni = sni;
        pkt.appType = identifyApp(sni);
        pkt.info = `TLS Client Hello [SNI: ${sni}]`;
      }
    }

    // DPI: HTTP Host
    if (pkt.hasTcp && !pkt.sni) {
      const httpStr = new TextDecoder('latin1').decode(payload.subarray(0, Math.min(payload.length, 1024)));
      if (httpStr.startsWith('GET ') || httpStr.startsWith('POST ') || httpStr.startsWith('HEAD ')) {
        const lines = httpStr.split('\r\n');
        const firstLine = lines[0];
        for (const line of lines) {
          if (line.toLowerCase().startsWith('host:')) {
            const host = line.slice(5).trim().split(':')[0];
            pkt.httpHost = host;
            pkt.appType = identifyApp(host);
            pkt.info = `HTTP ${firstLine.slice(0, 30)} [Host: ${host}]`;
            break;
          }
        }
      }
    }

    // DPI: DNS Query
    if (pkt.hasUdp && (pkt.srcPort === 53 || pkt.destPort === 53) && payload.length >= 12) {
      const qdCount = (payload[4] << 8) | payload[5];
      if (qdCount > 0) {
        const domain = extractDnsDomain(payload, 12);
        if (domain) {
          pkt.dnsQuery = domain;
          pkt.appType = `DNS (${identifyApp(domain)})`;
          pkt.info = `DNS Query: ${domain}`;
        }
      }
    }
  }

  return pkt;
}

function extractTlsSni(payload: Uint8Array): string | null {
  try {
    let offset = 9; // Skip TLS record (5) + handshake type/len (4)
    offset += 2; // version
    offset += 32; // random
    if (offset >= payload.length) return null;

    const sessionIdLen = payload[offset];
    offset += 1 + sessionIdLen;
    if (offset + 2 > payload.length) return null;

    const cipherLen = (payload[offset] << 8) | payload[offset + 1];
    offset += 2 + cipherLen;
    if (offset >= payload.length) return null;

    const compLen = payload[offset];
    offset += 1 + compLen;
    if (offset + 2 > payload.length) return null;

    const extTotalLen = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;
    const extEnd = Math.min(payload.length, offset + extTotalLen);

    while (offset + 4 <= extEnd) {
      const extType = (payload[offset] << 8) | payload[offset + 1];
      const extLen = (payload[offset + 2] << 8) | payload[offset + 3];
      offset += 4;

      if (extType === 0x0000 && extLen >= 5) {
        const sniType = payload[offset + 2];
        const sniLen = (payload[offset + 3] << 8) | payload[offset + 4];
        if (sniType === 0 && offset + 5 + sniLen <= extEnd) {
          const sniBytes = payload.subarray(offset + 5, offset + 5 + sniLen);
          return new TextDecoder('ascii').decode(sniBytes);
        }
      }
      offset += extLen;
    }
  } catch {
    // ignore
  }
  return null;
}

function extractDnsDomain(payload: Uint8Array, startOffset: number): string | null {
  let offset = startOffset;
  const parts: string[] = [];

  while (offset < payload.length) {
    const len = payload[offset];
    if (len === 0) break;
    if (len > 63) break;
    offset++;
    if (offset + len > payload.length) break;
    parts.push(new TextDecoder('ascii').decode(payload.subarray(offset, offset + len)));
    offset += len;
  }

  return parts.length > 0 ? parts.join('.') : null;
}

export function identifyApp(host: string): string {
  const h = host.toLowerCase();
  if (h.includes('google')) return 'Google';
  if (h.includes('youtube')) return 'YouTube';
  if (h.includes('facebook')) return 'Facebook';
  if (h.includes('instagram')) return 'Instagram';
  if (h.includes('twitter') || h.includes('x.com')) return 'Twitter / X';
  if (h.includes('netflix')) return 'Netflix';
  if (h.includes('amazon')) return 'Amazon';
  if (h.includes('microsoft')) return 'Microsoft';
  if (h.includes('apple')) return 'Apple';
  if (h.includes('whatsapp')) return 'WhatsApp';
  if (h.includes('telegram')) return 'Telegram';
  if (h.includes('tiktok')) return 'TikTok';
  if (h.includes('spotify')) return 'Spotify';
  if (h.includes('zoom')) return 'Zoom';
  if (h.includes('discord')) return 'Discord';
  if (h.includes('github')) return 'GitHub';
  if (h.includes('cloudflare')) return 'Cloudflare';
  if (h.includes('httpbin')) return 'HTTPBin';
  if (h.includes('example')) return 'Example Domain';
  return host;
}
