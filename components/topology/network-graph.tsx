'use client';

import { useCallback, useEffect, useState, useMemo } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Position,
  NodeTypes,
} from 'reactflow';
import 'reactflow/dist/style.css';
import './topology.css';
import { SensorNode } from './nodes/sensor-node';
import { RouterNode } from './nodes/router-node';
import { StationNode } from './nodes/station-node';
import { toast } from 'sonner';
import { Wifi, WifiOff, RefreshCw } from 'lucide-react';

interface TopologyData {
  nodes: any[];
  edges: any[];
  metadata: any;
}

export function NetworkGraph() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [useMockData, setUseMockData] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const nodeTypes: NodeTypes = useMemo(() => ({
    sensor: SensorNode,
    router: RouterNode,
    station: StationNode,
  }), []);

  // Fetch topology data
  const fetchTopology = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/topology');
      
      if (!response.ok) throw new Error('Failed to fetch topology');
      
      const result = await response.json();
      const topologyData: TopologyData = result.data;

      // Handle empty sensor state
      if (!topologyData.nodes || topologyData.nodes.length === 0) {
        setNodes([]);
        setEdges([]);
        toast.info('No sensors detected', {
          description: 'Waiting for Raspberry Pi sensors to come online...',
        });
        return;
      }

      // Convert topology data to ReactFlow format
      const rfNodes = topologyData.nodes.map((node, idx) => {
        const nodeType = node.type;
        const row = Math.floor(idx / 4);
        const col = idx % 4;

        return {
          id: node.id,
          data: {
            label: node.label,
            type: node.type,
            ...node,
          },
          position: { x: col * 400, y: row * 300 },
          type: nodeType,
        };
      });

      const rfEdges = topologyData.edges.map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        animated: edge.type === 'detection',
        label: edge.type === 'detection' ? `${edge.signal_strength}dBm` : edge.connection_status,
        style: {
          stroke: edge.type === 'detection' ? '#3b82f6' : '#8b5cf6',
          strokeWidth: 2,
        },
      }));

      setNodes(rfNodes);
      setEdges(rfEdges);
      
      toast.success('Network topology loaded', {
        description: `${topologyData.metadata.total_nodes} nodes, ${topologyData.metadata.shared_nodes_count} shared`,
      });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMsg);
      toast.error('Failed to load topology', {
        description: errorMsg,
      });
      setNodes([]);
      setEdges([]);
    } finally {
      setLoading(false);
    }
  }, [setNodes, setEdges]);

  useEffect(() => {
    fetchTopology();
  }, [fetchTopology]);

  const handleNodeClick = useCallback((event: any, node: Node) => {
    setSelectedNode(node.data);
  }, []);

  if (loading) {
    return (
      <div className="w-full h-full flex items-center justify-center bg-slate-900">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-slate-300">Loading network topology...</p>
        </div>
      </div>
    );
  }

  // Empty state: No sensors detected
  if (nodes.length === 0 && !error) {
    return (
      <div className="w-full h-full flex items-center justify-center bg-slate-900">
        <div className="text-center max-w-md">
          <div className="flex justify-center mb-6">
            <div className="bg-slate-800/50 p-6 rounded-full border-2 border-slate-700">
              <WifiOff className="w-12 h-12 text-slate-400" />
            </div>
          </div>
          <h2 className="text-2xl font-bold text-white mb-2">No Sensors Connected</h2>
          <p className="text-slate-300 mb-6">
            Searching for active ZeinaGuard sensors... Please ensure your Raspberry Pi units are online.
          </p>
          <div className="space-y-3">
            <button
              onClick={fetchTopology}
              className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
            >
              <RefreshCw className="w-4 h-4" />
              Retry Connection
            </button>
            <button
              onClick={() => setUseMockData(!useMockData)}
              className="w-full px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-100 rounded-lg font-medium transition-colors text-sm"
            >
              {useMockData ? 'Toggle: Using Mock Data' : 'Toggle: Using Real Data'}
            </button>
          </div>
          <div className="mt-6 p-4 bg-slate-800 border border-slate-700 rounded-lg">
            <p className="text-xs text-slate-400 uppercase font-semibold mb-2">Sensor Status</p>
            <ul className="text-sm text-slate-300 space-y-1 text-left">
              <li className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-red-500" />
                Raspberry Pi 1: Offline
              </li>
              <li className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-red-500" />
                Raspberry Pi 2: Offline
              </li>
            </ul>
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error && nodes.length === 0) {
    return (
      <div className="w-full h-full flex items-center justify-center bg-slate-900">
        <div className="text-center max-w-md">
          <div className="flex justify-center mb-6">
            <div className="bg-red-900/30 p-6 rounded-full border-2 border-red-700">
              <WifiOff className="w-12 h-12 text-red-500" />
            </div>
          </div>
          <h2 className="text-2xl font-bold text-white mb-2">Connection Error</h2>
          <p className="text-slate-300 mb-4">
            Unable to connect to the topology service.
          </p>
          <div className="bg-slate-800 border border-red-700/50 rounded-lg p-4 mb-6">
            <p className="text-xs text-red-400 font-mono text-left">{error}</p>
          </div>
          <button
            onClick={fetchTopology}
            className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex w-full h-full bg-slate-900">
      {/* Graph */}
      <div className="flex-1 relative">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={handleNodeClick}
          nodeTypes={nodeTypes}
          fitView
        >
          <Background color="#1e293b" gap={16} />
          <Controls />
        </ReactFlow>

        {/* Top-right Debug/Test Controls */}
        <div className="absolute top-4 right-4 flex gap-2">
          <button
            onClick={fetchTopology}
            title="Refresh topology data"
            className="p-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg text-slate-300 hover:text-white transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => {
              setUseMockData(!useMockData);
              setTimeout(() => fetchTopology(), 100);
            }}
            title="Toggle between mock and real data"
            className="px-3 py-2 text-xs bg-slate-800 hover:bg-slate-700 border border-slate-600 rounded-lg text-slate-300 hover:text-white transition-colors font-medium"
          >
            {useMockData ? 'Mock' : 'Real'} Data
          </button>
        </div>
      </div>

      {/* Node Details Panel */}
      {selectedNode && (
        <div className="w-80 bg-slate-800 border-l border-slate-700 p-6 overflow-y-auto h-full max-h-screen">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-white">Node Details</h3>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-slate-400 hover:text-white text-xl font-bold"
            >
              ✕
            </button>
          </div>

          {/* Node Info */}
          <div className="space-y-4">
            {/* Type & Label */}
            <div className="p-3 bg-slate-900/50 rounded-lg border border-slate-700">
              <p className="text-xs text-slate-500 uppercase font-semibold mb-1">Type</p>
              <p className="text-white font-semibold capitalize text-lg">{selectedNode.type}</p>
              <p className="text-blue-400 font-medium mt-2">{selectedNode.label}</p>
            </div>

            {/* MAC Address */}
            {selectedNode.mac_address && (
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold">MAC Address</p>
                <p className="text-white font-mono text-sm bg-slate-900 p-2 rounded border border-slate-700 mt-1">
                  {selectedNode.mac_address}
                </p>
              </div>
            )}

            {/* Signal Strength (RSSI) */}
            {selectedNode.signal_strength && (
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold">Signal Strength (RSSI)</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className="flex-1 bg-slate-900 rounded h-2">
                    <div
                      className={`h-full rounded transition-all ${
                        selectedNode.signal_strength > -50 ? 'bg-green-500' :
                        selectedNode.signal_strength > -70 ? 'bg-yellow-500' : 'bg-red-500'
                      }`}
                      style={{
                        width: `${Math.max(0, Math.min(100, (selectedNode.signal_strength + 100) * 1.2))}%`
                      }}
                    />
                  </div>
                  <span className="text-white font-mono text-sm">{selectedNode.signal_strength} dBm</span>
                </div>
              </div>
            )}

            {/* Location */}
            {selectedNode.location && (
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold">Location</p>
                <p className="text-white mt-1">{selectedNode.location}</p>
              </div>
            )}

            {/* SSID */}
            {selectedNode.ssid && (
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold">SSID</p>
                <p className="text-white mt-1">{selectedNode.ssid}</p>
              </div>
            )}

            {/* Security */}
            {selectedNode.security && (
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold">Security</p>
                <p className={`mt-1 font-medium ${
                  selectedNode.security === 'Open' ? 'text-red-400' :
                  selectedNode.security === 'WEP' ? 'text-orange-400' :
                  selectedNode.security === 'WPA2' ? 'text-green-400' : 'text-blue-400'
                }`}>
                  {selectedNode.security}
                </p>
              </div>
            )}

            {/* Device Type */}
            {selectedNode.device_type && (
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold">Device Type</p>
                <p className="text-white mt-1">{selectedNode.device_type}</p>
              </div>
            )}

            {/* Status */}
            {selectedNode.status && (
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold">Status</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`w-2 h-2 rounded-full ${
                    selectedNode.status === 'online' || selectedNode.status === 'connected' ? 'bg-green-500' : 'bg-red-500'
                  }`} />
                  <p className="text-white capitalize">{selectedNode.status}</p>
                </div>
              </div>
            )}

            {/* Last Seen / Last Activity */}
            {(selectedNode.last_seen || selectedNode.last_activity) && (
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold">Last Seen</p>
                <p className="text-white text-sm mt-1">
                  {new Date(selectedNode.last_seen || selectedNode.last_activity).toLocaleString()}
                </p>
              </div>
            )}

            {/* Shared Coverage Alert */}
            {selectedNode.is_shared && (
              <div className="p-4 bg-yellow-900/30 border-2 border-yellow-600 rounded-lg">
                <p className="text-xs text-yellow-400 uppercase font-bold mb-1">⭐ Shared Coverage</p>
                <p className="text-yellow-300 text-sm">
                  This node is visible/connected to multiple sensors. This indicates overlapping coverage or device roaming.
                </p>
              </div>
            )}

            {/* Threat Alert */}
            {selectedNode.is_suspicious && (
              <div className="p-4 bg-red-900/30 border-2 border-red-600 rounded-lg animate-pulse">
                <p className="text-xs text-red-400 uppercase font-bold mb-1">🚨 Security Threat</p>
                <p className="text-red-300 text-sm">
                  This node has been flagged as a potential security threat. Review immediately.
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
