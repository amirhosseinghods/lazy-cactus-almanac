import { simulateLatency } from '../simulate-latency';
import type { VPNClient, VPNPeer, VPNProtocol, VPNServer } from '../types';
import { clone, commit, nextId, state } from './store';

export const vpn = {
  async listClients(routerId: string): Promise<VPNClient[]> {
    await simulateLatency(50, 150);
    return clone(state.current.vpnClients.filter((c) => c.routerId === routerId));
  },
  async createClient(input: Omit<VPNClient, 'id'>): Promise<VPNClient> {
    await simulateLatency();
    const client: VPNClient = { ...input, id: nextId('vpnc') };
    state.current.vpnClients.push(client);
    commit();
    return clone(client);
  },
  async updateClient(id: string, patch: Partial<VPNClient>): Promise<VPNClient | undefined> {
    await simulateLatency();
    const list = state.current.vpnClients;
    const idx = list.findIndex((c) => c.id === id);
    if (idx === -1) return undefined;
    list[idx] = { ...list[idx], ...patch };
    commit();
    return clone(list[idx]);
  },
  async deleteClient(id: string): Promise<void> {
    await simulateLatency();
    state.current.vpnClients = state.current.vpnClients.filter((c) => c.id !== id);
    commit();
  },
  async listServers(routerId: string): Promise<VPNServer[]> {
    await simulateLatency(50, 150);
    return clone(state.current.vpnServers.filter((s) => s.routerId === routerId));
  },
  async createServer(input: Omit<VPNServer, 'id'>): Promise<VPNServer> {
    await simulateLatency();
    const server: VPNServer = { ...input, id: nextId('vpns') };
    state.current.vpnServers.push(server);
    commit();
    return clone(server);
  },
  async deleteServer(id: string): Promise<void> {
    await simulateLatency();
    state.current.vpnServers = state.current.vpnServers.filter((s) => s.id !== id);
    state.current.vpnPeers = state.current.vpnPeers.filter((p) => p.serverId !== id);
    commit();
  },
  async listPeers(routerId: string): Promise<VPNPeer[]> {
    await simulateLatency(50, 150);
    return clone(state.current.vpnPeers.filter((p) => p.routerId === routerId));
  },
  async createPeer(input: Omit<VPNPeer, 'id'>): Promise<VPNPeer> {
    await simulateLatency();
    const peer: VPNPeer = { ...input, id: nextId('vpnp') };
    state.current.vpnPeers.push(peer);
    commit();
    return clone(peer);
  },
  async updatePeer(id: string, patch: Partial<VPNPeer>): Promise<VPNPeer | undefined> {
    await simulateLatency();
    const list = state.current.vpnPeers;
    const idx = list.findIndex((p) => p.id === id);
    if (idx === -1) return undefined;
    list[idx] = { ...list[idx], ...patch };
    commit();
    return clone(list[idx]);
  },
  async deletePeer(id: string): Promise<void> {
    await simulateLatency();
    state.current.vpnPeers = state.current.vpnPeers.filter((p) => p.id !== id);
    commit();
  },
};

export const getProtocolOptions = (): VPNProtocol[] => [
  'wireguard',
  'l2tp',
  'openvpn',
  'pptp',
  'sstp',
  'ikev2',
  'v2ray',
];
