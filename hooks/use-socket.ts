/**
 * useSocket Hook - Real-time WebSocket connection
 * Manages Socket.io connection for threat events and sensor status
 */

import { useEffect, useRef, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';

export interface ThreatEvent {
  type: 'threat_detected';
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  threat_type: string;
  data: {
    id: number;
    threat_type: string;
    severity: string;
    source_mac: string;
    ssid: string;
    detected_by: number;
    description: string;
    signal_strength: number;
    packet_count: number;
    is_resolved: boolean;
    created_at: string;
  };
}

export interface SensorStatusEvent {
  type: 'sensor_status';
  timestamp: string;
  data: {
    sensor_id: string | number;
    hostname?: string;
    status: 'online' | 'offline' | 'degraded';
    signal_strength?: number;
    cpu_usage?: number;
    memory_usage?: number;
    uptime?: number;
    last_heartbeat?: string;
  };
}

export interface LiveScanNetwork {
  ssid: string;
  bssid: string;
  channel: number;
  signal: number;
  encryption: string;
  manufacturer: string;
  classification: 'LEGIT' | 'SUSPICIOUS' | 'ROGUE';
  score: number;
  clients?: number;
  distance?: number;
}

export interface LiveScanEvent {
  sensor_id: string;
  hostname: string;
  sent_at: string;
  networks: LiveScanNetwork[];
}

export type SocketEvent = ThreatEvent | SensorStatusEvent;

interface UseSocketOptions {
  onThreatEvent?: (event: ThreatEvent) => void;
  onSensorStatus?: (event: SensorStatusEvent) => void;
  onLiveScan?: (event: LiveScanEvent) => void;
  autoConnect?: boolean;
}

/**
 * Hook to manage WebSocket connection
 */
export function useSocket(options: UseSocketOptions = {}) {
  const {
    onThreatEvent,
    onSensorStatus,
    onLiveScan,
    autoConnect = true,
  } = options;

  const socketRef = useRef<Socket | null>(null);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;

  /**
   * Connect to WebSocket server
   */
  const connect = useCallback(() => {
    if (socketRef.current?.connected) {
      return;
    }

    try {
      // Connect via Next.js /socket.io/* rewrite → backend Flask-SocketIO on port 8000
      // NEXT_PUBLIC_SOCKET_URL can override (e.g. for local sensor testing)
      const socketUrl = process.env.NEXT_PUBLIC_SOCKET_URL || '';

      socketRef.current = io(socketUrl, {
        path: '/socket.io',
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: maxReconnectAttempts,
        transports: ['polling', 'websocket'],
      });

      // Connection events
      socketRef.current.on('connect', () => {
        console.log('[Socket.io] Connected to server');
        reconnectAttempts.current = 0;
        subscribeToThreats();
        subscribeTosensors();
      });

      socketRef.current.on('disconnect', (reason) => {
        console.log('[Socket.io] Disconnected:', reason);
      });

      socketRef.current.on('connect_error', (error) => {
        console.error('[Socket.io] Connection error:', error);
        reconnectAttempts.current++;
      });

      // Threat event listener
      socketRef.current.on('threat_event', (event: ThreatEvent) => {
        console.log('[Socket.io] Threat event received:', event);
        onThreatEvent?.(event);
      });

      // Sensor status listener
      socketRef.current.on('sensor_status', (event: SensorStatusEvent) => {
        console.log('[Socket.io] Sensor status received:', event);
        onSensorStatus?.(event);
      });

      // Live scan listener (real-time AP scan batches from physical sensors)
      socketRef.current.on('live_scan', (event: LiveScanEvent) => {
        console.log('[Socket.io] Live scan batch received:', event.sensor_id, event.networks?.length, 'networks');
        onLiveScan?.(event);
      });

      // Connection response
      socketRef.current.on('connection_response', (data) => {
        console.log('[Socket.io] Connection response:', data);
      });

      // Subscription response
      socketRef.current.on('subscription_response', (data) => {
        console.log('[Socket.io] Subscription response:', data);
      });
    } catch (error) {
      console.error('[Socket.io] Failed to connect:', error);
    }
  }, [onThreatEvent, onSensorStatus]);

  /**
   * Disconnect from WebSocket server
   */
  const disconnect = useCallback(() => {
    if (socketRef.current?.connected) {
      socketRef.current.disconnect();
    }
  }, []);

  /**
   * Subscribe to threat events
   */
  const subscribeToThreats = useCallback(() => {
    if (socketRef.current?.connected) {
      socketRef.current.emit('subscribe_threats');
    }
  }, []);

  /**
   * Unsubscribe from threat events
   */
  const unsubscribeFromThreats = useCallback(() => {
    if (socketRef.current?.connected) {
      socketRef.current.emit('unsubscribe_threats');
    }
  }, []);

  /**
   * Subscribe to sensor status updates
   */
  const subscribeTosensors = useCallback(() => {
    if (socketRef.current?.connected) {
      socketRef.current.emit('subscribe_sensors');
    }
  }, []);

  /**
   * Unsubscribe from sensor updates
   */
  const unsubscribeFromSensors = useCallback(() => {
    if (socketRef.current?.connected) {
      socketRef.current.emit('unsubscribe_sensors');
    }
  }, []);

  /**
   * Check if connected
   */
  const isConnected = useCallback(() => {
    return socketRef.current?.connected ?? false;
  }, []);

  /**
   * Get socket instance (for direct access if needed)
   */
  const getSocket = useCallback(() => {
    return socketRef.current;
  }, []);

  /**
   * Auto-connect on mount
   */
  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [autoConnect, connect, disconnect]);

  return {
    connect,
    disconnect,
    subscribeToThreats,
    unsubscribeFromThreats,
    subscribeTosensors,
    unsubscribeFromSensors,
    isConnected,
    getSocket,
  };
}

/**
 * Hook to listen for threat events
 */
export function useThreatEvents(onEvent?: (event: ThreatEvent) => void) {
  useSocket({
    onThreatEvent: onEvent,
  });
}

/**
 * Hook to listen for sensor status updates
 */
export function useSensorStatus(onEvent?: (event: SensorStatusEvent) => void) {
  useSocket({
    onSensorStatus: onEvent,
  });
}
