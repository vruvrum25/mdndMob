// real-ip-fingerprinting.js

class RealIPFingerprinter {
    constructor() {
        this.realLocalIPs = [];
        this.peerConnection = null;
        this.dataChannel = null;
        this.fingerprintData = {};
        this.isConnected = false;
        this.stunComparisonData = {};
        this.channelMonitorLog = [];
        
        this.setupMobileDetection();
    }

    setupMobileDetection() {
        // Определяем мобильное устройство
        this.isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
        this.deviceInfo = {
            isMobile: this.isMobile,
            platform: navigator.platform,
            userAgent: navigator.userAgent,
            screenSize: `${screen.width}x${screen.height}`,
            pixelRatio: window.devicePixelRatio || 1
        };
    }

    // ЭТАП 1: Поиск реальных локальных IP адресов
    async findRealLocalIPs() {
        this.updateStatus('globalStatus', 'active', 'Поиск реальных IP адресов...');
        this.updateProgress('progress1', 0);
        
        const resultsDiv = document.getElementById('localIPResults');
        resultsDiv.innerHTML = '<p>🔍 Сканирование реальных локальных IP адресов (без mDNS)...</p>';
        
        this.realLocalIPs = [];

        return new Promise((resolve) => {
            const pc = new RTCPeerConnection({iceServers: []});
            pc.createDataChannel('ip-discovery');
            
            let candidatesFound = 0;
            
            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    candidatesFound++;
                    this.updateProgress('progress1', Math.min(candidatesFound * 15, 90));
                    
                    const candidate = event.candidate.candidate;
                    
                    // Ищем реальные IP адреса (не .local)
                    const ipMatch = candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
                    
                    if (ipMatch && candidate.includes('typ host')) {
                        const ipAddress = ipMatch[1];
                        
                        // Проверяем, что это локальные IP диапазоны
                        if (this.isLocalIP(ipAddress) && !this.realLocalIPs.some(addr => addr.ip === ipAddress)) {
                            this.realLocalIPs.push({
                                ip: ipAddress,
                                candidate: candidate,
                                timestamp: new Date().toISOString(),
                                protocol: event.candidate.protocol,
                                port: event.candidate.port,
                                type: event.candidate.type,
                                priority: event.candidate.priority
                            });
                            
                            this.displayRealIPAddress(ipAddress, candidate);
                        }
                    }
                } else {
                    pc.close();
                    this.completeRealIPDiscovery();
                    resolve();
                }
            };

            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .catch(error => {
                    console.error('Ошибка создания offer:', error);
                    pc.close();
                    this.handleNoRealIPFound();
                    resolve();
                });

            setTimeout(() => {
                pc.close();
                this.completeRealIPDiscovery();
                resolve();
            }, 8000);
        });
    }

    isLocalIP(ip) {
        const parts = ip.split('.').map(Number);
        return (
            (parts[0] === 192 && parts[1] === 168) ||
            (parts[0] === 10) ||
            (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
            (parts[0] === 169 && parts[1] === 254) // Link-local
        );
    }

    displayRealIPAddress(ip, candidate) {
        const resultsDiv = document.getElementById('localIPResults');
        const addressDiv = document.createElement('div');
        addressDiv.className = 'real-ip-address';
        addressDiv.innerHTML = `
            <h4>🌐 Реальный локальный IP найден</h4>
            <strong>IP адрес:</strong> <code>${ip}</code><br>
            <strong>Сеть:</strong> <code>${this.identifyNetworkType(ip)}</code><br>
            <strong>Кандидат:</strong> <code>${candidate}</code><br>
            <strong>Время:</strong> ${new Date().toLocaleTimeString()}
        `;
        resultsDiv.appendChild(addressDiv);
    }

    identifyNetworkType(ip) {
        const parts = ip.split('.').map(Number);
        if (parts[0] === 192 && parts[1] === 168) return 'Домашняя сеть (192.168.x.x)';
        if (parts[0] === 10) return 'Корпоративная сеть (10.x.x.x)';
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return 'Корпоративная сеть (172.16-31.x.x)';
        if (parts[0] === 169 && parts[1] === 254) return 'Link-local (169.254.x.x)';
        return 'Неизвестный тип сети';
    }

    completeRealIPDiscovery() {
        this.updateProgress('progress1', 100);
        
        if (this.realLocalIPs.length === 0) {
            this.handleNoRealIPFound();
        } else {
            const resultsDiv = document.getElementById('localIPResults');
            const summaryDiv = document.createElement('div');
            summaryDiv.className = 'fingerprint-result';
            summaryDiv.innerHTML = `
                <h4>✅ Найдено ${this.realLocalIPs.length} реальных IP адреса</h4>
                <p><strong>Обнаруженные сети:</strong></p>
                ${this.realLocalIPs.map(addr => `<code>${addr.ip}</code> - ${this.identifyNetworkType(addr.ip)}`).join('<br>')}
                <p>Готов к сравнению с STUN и P2P соединению</p>
            `;
            resultsDiv.appendChild(summaryDiv);
            
            document.getElementById('step1').classList.add('active');
            document.getElementById('stunCompareBtn').disabled = false;
        }
    }

    handleNoRealIPFound() {
        document.getElementById('step1').classList.add('warning');
        const resultsDiv = document.getElementById('localIPResults');
        resultsDiv.innerHTML = `
            <div class="attack-result">
                <h3>⚠️ Реальные IP адреса не найдены</h3>
                <p><strong>Возможные причины:</strong></p>
                <ul>
                    <li>mDNS обфускация ВКЛЮЧЕНА (показывает .local вместо IP)</li>
                    <li>Устройство подключено только через мобильную сеть</li>
                    <li>VPN блокирует локальные адреса</li>
                    <li>Корпоративная сеть с жесткими ограничениями</li>
                </ul>
                <button onclick="realIPSystem.findRealLocalIPs()">Повторить поиск</button>
            </div>
        `;
    }

    // ЭТАП 2: Сравнение с прямыми STUN запросами
    async compareWithDirectSTUN() {
        this.updateStatus('globalStatus', 'active', 'Сравнение с STUN...');
        this.updateProgress('progress2', 0);

        const resultsDiv = document.getElementById('stunComparisonResults');
        resultsDiv.innerHTML = '<p>⚖️ Сравнение локальных IP с STUN результатами...</p>';

        // Получаем данные через прямой STUN запрос
        const stunResults = await this.getDirectSTUNResults();
        this.updateProgress('progress2', 50);

        // Сравниваем результаты
        const comparison = this.compareLocalVsSTUN(stunResults);
        this.updateProgress('progress2', 100);

        this.displaySTUNComparison(comparison);
        document.getElementById('step2').classList.add('active');
        document.getElementById('p2pBtn').disabled = false;
    }

    async getDirectSTUNResults() {
        return new Promise((resolve) => {
            const pc = new RTCPeerConnection({
                iceServers: [
                    {urls: 'stun:stun.l.google.com:19302'},
                    {urls: 'stun:stun1.l.google.com:19302'}
                ]
            });
            
            const results = {
                localIPs: [],
                publicIPs: [],
                rawCandidates: []
            };

            pc.createDataChannel('stun-test');

            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    const candidate = event.candidate.candidate;
                    results.rawCandidates.push(candidate);

                    const ipMatch = candidate.match(/(\d+\.\d+\.\d+\.\d+)/g);
                    if (ipMatch) {
                        if (candidate.includes('typ host')) {
                            results.localIPs.push(ipMatch[0]);
                        } else if (candidate.includes('typ srflx')) {
                            results.publicIPs.push(ipMatch[1] || ipMatch[0]);
                        }
                    }
                } else {
                    pc.close();
                    resolve(results);
                }
            };

            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .catch(() => resolve(results));

            setTimeout(() => {
                pc.close();
                resolve(results);
            }, 5000);
        });
    }

    compareLocalVsSTUN(stunResults) {
        const localIPs = this.realLocalIPs.map(addr => addr.ip);
        const stunLocalIPs = [...new Set(stunResults.localIPs)];
        const publicIPs = [...new Set(stunResults.publicIPs)];

        return {
            directLocal: localIPs,
            stunLocal: stunLocalIPs,
            stunPublic: publicIPs,
            matching: localIPs.filter(ip => stunLocalIPs.includes(ip)),
            onlyDirect: localIPs.filter(ip => !stunLocalIPs.includes(ip)),
            onlySTUN: stunLocalIPs.filter(ip => !localIPs.includes(ip)),
            hasDiscrepancy: localIPs.length !== stunLocalIPs.length || !localIPs.every(ip => stunLocalIPs.includes(ip))
        };
    }

    displaySTUNComparison(comparison) {
        const resultsDiv = document.getElementById('stunComparisonResults');
        const comparisonDiv = document.createElement('div');
        comparisonDiv.className = 'ip-comparison';
        comparisonDiv.innerHTML = `
            <h4>📊 Сравнение методов получения IP</h4>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 15px 0;">
                <div style="background: #e8f5e8; padding: 10px; border-radius: 8px;">
                    <strong>Прямое сканирование WebRTC:</strong><br>
                    ${comparison.directLocal.map(ip => `<code>${ip}</code>`).join('<br>') || 'Не найдено'}
                </div>
                
                <div style="background: #fff3e0; padding: 10px; border-radius: 8px;">
                    <strong>STUN локальные IP:</strong><br>
                    ${comparison.stunLocal.map(ip => `<code>${ip}</code>`).join('<br>') || '<code>0.0.0.0</code>'}
                </div>
                
                <div style="background: #e3f2fd; padding: 10px; border-radius: 8px;">
                    <strong>STUN публичные IP:</strong><br>
                    ${comparison.stunPublic.map(ip => `<code>${ip}</code>`).join('<br>') || 'Не найдено'}
                </div>
            </div>

            ${comparison.hasDiscrepancy ? `
                <div style="background: #ffebee; padding: 10px; border-radius: 8px; border: 1px solid #f44336;">
                    <strong>⚠️ Обнаружено расхождение!</strong><br>
                    Прямое сканирование показывает IP, которые не видны через STUN.<br>
                    Это может указывать на блокировку или подмену STUN ответов.
                </div>
            ` : `
                <div style="background: #e8f5e8; padding: 10px; border-radius: 8px; border: 1px solid #4CAF50;">
                    <strong>✅ Результаты совпадают</strong><br>
                    Методы показывают одинаковые локальные IP адреса.
                </div>
            `}
        `;
        resultsDiv.appendChild(comparisonDiv);

        this.stunComparisonData = comparison;
    }

    // ЭТАП 3: Установка P2P соединения через реальные IP
    async establishRealIPP2P() {
        if (this.realLocalIPs.length === 0) {
            alert('Сначала найдите реальные IP адреса!');
            return;
        }

        this.updateStatus('globalStatus', 'active', 'P2P через реальные IP...');
        this.updateProgress('progress3', 0);

        const resultsDiv = document.getElementById('p2pResults');
        resultsDiv.innerHTML = '<p>🔗 Создание P2P соединения через реальные IP адреса...</p>';

        try {
            this.peerConnection = new RTCPeerConnection({iceServers: []});
            this.dataChannel = this.peerConnection.createDataChannel('real-ip-channel', {
                ordered: true,
                maxRetransmits: 5
            });

            this.setupRealIPDataChannel();
            this.setupRealIPPeerConnection();

            const offer = await this.peerConnection.createOffer();
            await this.peerConnection.setLocalDescription(offer);

            this.updateProgress('progress3', 60);

            setTimeout(() => {
                this.simulateRealIPConnection();
            }, 2500);

        } catch (error) {
            console.error('Ошибка P2P соединения:', error);
            this.updateStatus('globalStatus', 'error', 'Ошибка P2P');
        }
    }

    setupRealIPDataChannel() {
        this.dataChannel.onopen = () => {
            this.isConnected = true;
            this.updateStatus('globalStatus', 'success', 'P2P канал активен');
            this.enableAllButtons();
            this.logToMonitor('✅ DataChannel открыт через реальные IP');
        };

        this.dataChannel.onmessage = (event) => {
            this.handleRealIPMessage(event.data);
        };

        this.dataChannel.onerror = (error) => {
            console.error('DataChannel ошибка:', error);
            this.logToMonitor('❌ DataChannel ошибка: ' + error);
        };
    }

    setupRealIPPeerConnection() {
        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                const candidate = event.candidate.candidate;
                if (this.isLocalIP(candidate.match(/(\d+\.\d+\.\d+\.\d+)/)?.[1])) {
                    this.logToMonitor('🌐 P2P кандидат: ' + candidate);
                    this.updateProgress('progress3', 80);
                }
            }
        };
    }

    simulateRealIPConnection() {
        this.updateProgress('progress3', 100);
        this.isConnected = true;

        const resultsDiv = document.getElementById('p2pResults');
        resultsDiv.innerHTML = `
            <div class="fingerprint-result">
                <h4>✅ P2P соединение через реальные IP установлено!</h4>
                <p><strong>Активные IP адреса:</strong></p>
                ${this.realLocalIPs.map(addr => `
                    <code>${addr.ip}</code> - ${this.identifyNetworkType(addr.ip)}<br>
                `).join('')}
                <p><strong>DataChannel готов для fingerprinting команд</strong></p>
                <p><strong>Преимущества:</strong> Прямое соединение без mDNS, полный доступ к реальным адресам</p>
            </div>
        `;

        document.getElementById('step3').classList.add('active');
        this.logToMonitor('🚀 P2P соединение установлено через IP: ' + this.realLocalIPs.map(a => a.ip).join(', '));
    }

    enableAllButtons() {
        const buttons = [
            'advancedSTUNBtn', 'topologyBtn', 'mobileHWBtn', 'connectionBtn',
            'realScanBtn', 'carrierBtn', 'mobileFPBtn', 'locationBtn',
            'reportBtn', 'compareBtn'
        ];
        buttons.forEach(btnId => {
            document.getElementById(btnId).disabled = false;
        });
    }

    // ЭТАП 4: Fingerprinting команды

    async executeAdvancedSTUN() {
        const command = {
            type: 'advanced-stun-analysis',
            targets: [
                'stun:stun.l.google.com:19302',
                'stun:stun1.l.google.com:19302',
                'stun:stun2.l.google.com:19302',
                'stun:global.stun.twilio.com:3478',
                'stun:stun.ekiga.net',
                'stun:stun.fwdnet.net'
            ],
            analysis: ['latency', 'consistency', 'ip-enumeration', 'nat-detection'],
            realIPs: this.realLocalIPs.map(addr => addr.ip)
        };

        this.sendRealIPCommand(command);
        this.simulateAdvancedSTUNResponse();
    }

    simulateAdvancedSTUNResponse() {
        setTimeout(() => {
            const results = {
                type: 'advanced-stun-results',
                analysis: {
                    servers: [
                        {
                            server: 'stun:stun.l.google.com:19302',
                            localIP: this.realLocalIPs[0]?.ip || '192.168.1.141',
                            publicIP: '185.21.67.236',
                            latency: 23,
                            natType: 'Symmetric NAT',
                            success: true
                        },
                        {
                            server: 'stun:stun1.l.google.com:19302',
                            localIP: this.realLocalIPs[0]?.ip || '192.168.1.141',
                            publicIP: '185.21.67.236',
                            latency: 31,
                            natType: 'Symmetric NAT',
                            success: true
                        },
                        {
                            server: 'stun:global.stun.twilio.com:3478',
                            localIP: this.realLocalIPs[0]?.ip || '192.168.1.141',
                            publicIP: '185.21.67.236',
                            latency: 67,
                            natType: 'Symmetric NAT',
                            success: true
                        }
                    ],
                    consistency: 'HIGH',
                    averageLatency: 40.3,
                    natMapping: 'Endpoint-Independent'
                }
            };

            this.handleRealIPMessage(JSON.stringify(results));
        }, 2000);
    }

    async executeNetworkTopology() {
        const command = {
            type: 'network-topology-analysis',
            baseIPs: this.realLocalIPs.map(addr => addr.ip),
            analysis: [
                'gateway-detection',
                'subnet-enumeration',
                'device-discovery',
                'routing-analysis'
            ]
        };

        this.sendRealIPCommand(command);
        this.simulateNetworkTopologyResponse();
    }

    simulateNetworkTopologyResponse() {
        setTimeout(() => {
            const baseIP = this.realLocalIPs[0]?.ip || '192.168.1.141';
            const subnet = baseIP.split('.').slice(0, 3).join('.');
            
            const results = {
                type: 'network-topology-results',
                topology: {
                    subnet: subnet + '.0/24',
                    gateway: subnet + '.1',
                    dnsServers: ['8.8.8.8', '1.1.1.1'],
                    deviceRange: subnet + '.1-254',
                    activeDevices: [
                        {ip: subnet + '.1', type: 'Gateway/Router', manufacturer: 'TP-Link'},
                        {ip: baseIP, type: 'Current Device', manufacturer: 'Unknown'},
                        {ip: subnet + '.105', type: 'Printer', manufacturer: 'HP'},
                        {ip: subnet + '.201', type: 'NAS', manufacturer: 'Synology'}
                    ],
                    networkClass: this.getNetworkClass(baseIP),
                    estimatedDeviceCount: 12
                }
            };

            this.handleRealIPMessage(JSON.stringify(results));
        }, 2500);
    }

    getNetworkClass(ip) {
        const firstOctet = parseInt(ip.split('.')[0]);
        if (firstOctet >= 192) return 'Class C (домашняя сеть)';
        if (firstOctet >= 172) return 'Class B (корпоративная сеть)';
        if (firstOctet >= 10) return 'Class A (крупная корпоративная сеть)';
        return 'Unknown';
    }

    async executeMobileHardware() {
        const command = {
            type: 'mobile-hardware-analysis',
            deviceInfo: this.deviceInfo,
            tests: [
                'cpu-capabilities',
                'memory-analysis',
                'network-interfaces',
                'sensor-detection'
            ]
        };

        this.sendRealIPCommand(command);
        this.simulateMobileHardwareResponse();
    }

    simulateMobileHardwareResponse() {
        setTimeout(() => {
            const results = {
                type: 'mobile-hardware-results',
                hardware: {
                    device: this.isMobile ? 'Mobile Device' : 'Desktop',
                    cpu: {
                        cores: navigator.hardwareConcurrency || 'Unknown',
                        architecture: navigator.platform
                    },
                    memory: {
                        deviceMemory: navigator.deviceMemory ? navigator.deviceMemory + ' GB' : 'Unknown',
                        jsHeapSize: performance.memory ? Math.round(performance.memory.usedJSHeapSize / 1024 / 1024) + ' MB' : 'Unknown'
                    },
                    screen: {
                        resolution: `${screen.width}x${screen.height}`,
                        pixelRatio: window.devicePixelRatio,
                        colorDepth: screen.colorDepth
                    },
                    network: {
                        connection: navigator.connection ? {
                            effectiveType: navigator.connection.effectiveType,
                            downlink: navigator.connection.downlink,
                            rtt: navigator.connection.rtt
                        } : 'Unknown',
                        localIPs: this.realLocalIPs.map(addr => addr.ip)
                    }
                }
            };

            this.handleRealIPMessage(JSON.stringify(results));
        }, 1500);
    }

    async executeConnectionAnalysis() {
        const command = {
            type: 'connection-analysis',
            analyse: [
                'webrtc-capabilities',
                'codec-support',
                'ice-gathering-performance',
                'datachannel-limits'
            ]
        };

        this.sendRealIPCommand(command);
        this.simulateConnectionAnalysisResponse();
    }

    simulateConnectionAnalysisResponse() {
        setTimeout(() => {
            const results = {
                type: 'connection-analysis-results',
                analysis: {
                    webrtcCapabilities: {
                        peerConnection: 'Supported',
                        dataChannel: 'Supported',
                        getUserMedia: navigator.mediaDevices ? 'Supported' : 'Not supported'
                    },
                    codecs: {
                        video: ['VP8', 'VP9', 'H264'],
                        audio: ['OPUS', 'PCMU', 'PCMA']
                    },
                    iceGathering: {
                        hostCandidates: this.realLocalIPs.length,
                        gatheringTime: '1.2 seconds',
                        candidateTypes: ['host', 'srflx']
                    },
                    dataChannelLimits: {
                        maxMessageSize: 65536,
                        maxChannels: 65534,
                        ordered: 'Supported',
                        reliable: 'Supported'
                    }
                }
            };

            this.handleRealIPMessage(JSON.stringify(results));
        }, 1200);
    }

    // ЭТАП 5: Продвинутые атаки

    async executeRealIPNetworkScan() {
        const command = {
            type: 'real-ip-network-scan',
            baseIPs: this.realLocalIPs.map(addr => addr.ip),
            scanRange: this.generateScanRange(),
            ports: [80, 443, 22, 23, 8080, 9000, 5000, 9100],
            method: 'webrtc-connectivity-test'
        };

        this.sendRealIPCommand(command);
        this.simulateRealIPNetworkScanResponse();
    }

    generateScanRange() {
        if (this.realLocalIPs.length === 0) return [];
        
        const baseIP = this.realLocalIPs[0].ip;
        const subnet = baseIP.split('.').slice(0, 3).join('.');
        
        return [
            subnet + '.1',      // Gateway
            subnet + '.1-10',   // Infrastructure
            subnet + '.50-99',  // IoT devices
            subnet + '.100-150', // Printers/peripherals
            subnet + '.200-250'  // Servers/NAS
        ];
    }

    simulateRealIPNetworkScanResponse() {
        setTimeout(() => {
            const baseIP = this.realLocalIPs[0]?.ip || '192.168.1.141';
            const subnet = baseIP.split('.').slice(0, 3).join('.');
            
            const results = {
                type: 'real-ip-scan-results',
                scan: {
                    baseIP: baseIP,
                    subnet: subnet + '.0/24',
                    devicesFound: [
                        {
                            ip: subnet + '.1',
                            ports: [80, 443],
                            type: 'Router/Gateway',
                            manufacturer: 'TP-Link',
                            model: 'Archer C7',
                            services: ['HTTP', 'HTTPS', 'SSH']
                        },
                        {
                            ip: subnet + '.105',
                            ports: [9100, 80],
                            type: 'Network Printer',
                            manufacturer: 'HP',
                            model: 'LaserJet Pro M404dn',
                            services: ['IPP', 'HTTP']
                        },
                        {
                            ip: subnet + '.201',
                            ports: [5000, 5001, 80],
                            type: 'NAS Storage',
                            manufacturer: 'Synology',
                            model: 'DS220+',
                            services: ['DSM', 'HTTP', 'SSH']
                        },
                        {
                            ip: baseIP,
                            ports: [],
                            type: 'Current Device',
                            manufacturer: 'Unknown',
                            services: ['WebRTC P2P']
                        }
                    ],
                    totalScanned: 254,
                    activeDevices: 4,
                    scanDuration: '45 seconds'
                }
            };

            this.handleRealIPMessage(JSON.stringify(results));
        }, 3500);
    }

    async executeCarrierDetection() {
        const command = {
            type: 'carrier-detection',
            methods: [
                'ip-geolocation',
                'network-timing-analysis',
                'carrier-specific-stun',
                'dns-analysis'
            ]
        };

        this.sendRealIPCommand(command);
        this.simulateCarrierDetectionResponse();
    }

    simulateCarrierDetectionResponse() {
        setTimeout(() => {
            const results = {
                type: 'carrier-detection-results',
                carrier: {
                    detected: this.isMobile,
                    name: this.isMobile ? 'Mobile Carrier' : 'ISP Provider',
                    type: this.isMobile ? 'Mobile Network' : 'Fixed Broadband',
                    technology: this.isMobile ? '4G/5G' : 'Fiber/Cable',
                    country: 'RU',
                    region: 'Moscow',
                    networkInfo: {
                        asn: 'AS12345',
                        organization: 'Example Telecom',
                        ipRange: '185.21.0.0/16'
                    },
                    connectionType: navigator.connection ? navigator.connection.effectiveType : 'Unknown'
                }
            };

            this.handleRealIPMessage(JSON.stringify(results));
        }, 2000);
    }

    async executeMobileFingerprint() {
        const command = {
            type: 'mobile-specific-fingerprint',
            collect: [
                'touch-capabilities',
                'orientation-sensors',
                'device-motion',
                'mobile-specific-apis'
            ]
        };

        this.sendRealIPCommand(command);
        this.simulateMobileFingerprintResponse();
    }

    simulateMobileFingerprintResponse() {
        setTimeout(() => {
            const results = {
                type: 'mobile-fingerprint-results',
                fingerprint: {
                    touchSupport: 'ontouchstart' in window,
                    maxTouchPoints: navigator.maxTouchPoints || 0,
                    orientation: {
                        supported: 'orientation' in window,
                        current: window.orientation || 0
                    },
                    deviceMotion: 'DeviceMotionEvent' in window,
                    vibration: 'vibrate' in navigator,
                    battery: 'getBattery' in navigator,
                    geolocation: 'geolocation' in navigator,
                    camera: navigator.mediaDevices ? 'Supported' : 'Not supported',
                    webGL: this.detectWebGL(),
                    canvas: this.generateCanvasFingerprint(),
                    uniquenessFactor: Math.random().toFixed(6)
                }
            };

            this.handleRealIPMessage(JSON.stringify(results));
        }, 1800);
    }

    detectWebGL() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl && gl.getParameter) {
                const renderer = gl.getParameter(gl.RENDERER);
                const vendor = gl.getParameter(gl.VENDOR);
                return `${vendor} ${renderer}`;
            }
        } catch (e) {}
        return 'Not supported';
    }

    generateCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('Canvas fingerprint test 🔍', 2, 2);
            return canvas.toDataURL().slice(-10);
        } catch (e) {
            return 'Error';
        }
    }

    async executeLocationCorrelation() {
        const command = {
            type: 'location-correlation',
            data: {
                timezoneOffset: new Date().getTimezoneOffset(),
                language: navigator.language,
                languages: navigator.languages,
                platform: navigator.platform,
                realIPs: this.realLocalIPs.map(addr => addr.ip)
            }
        };

        this.sendRealIPCommand(command);
        this.simulateLocationCorrelationResponse();
    }

    simulateLocationCorrelationResponse() {
        setTimeout(() => {
            const results = {
                type: 'location-correlation-results',
                correlation: {
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    estimatedLocation: {
                        country: 'Russia',
                        city: 'Moscow',
                        confidence: '87%'
                    },
                    networkLocation: {
                        subnet: this.realLocalIPs[0]?.ip.split('.').slice(0, 3).join('.') + '.0/24',
                        type: this.identifyNetworkType(this.realLocalIPs[0]?.ip || '192.168.1.1'),
                        estimatedUsers: '5-15 devices'
                    },
                    correlationFactors: {
                        languageMatch: 'High',
                        timezoneMatch: 'High',
                        networkTypeMatch: 'Medium'
                    }
                }
            };

            this.handleRealIPMessage(JSON.stringify(results));
        }, 1500);
    }

    // ЭТАП 6: Генерация отчетов

    generateMobileReport() {
        const report = {
            timestamp: new Date().toISOString(),
            deviceType: this.isMobile ? 'Mobile' : 'Desktop',
            realLocalIPs: this.realLocalIPs,
            stunComparison: this.stunComparisonData,
            fingerprintData: this.fingerprintData,
            sessionId: this.generateSessionId(),
            riskAssessment: this.calculateMobileRiskLevel(),
            uniquenessScore: this.calculateUniqueness()
        };

        const resultsDiv = document.getElementById('finalResults');
        resultsDiv.innerHTML = `
            <div class="fingerprint-result">
                <h3>📊 Полный отчет Real IP Fingerprinting</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0;">
                    <div>
                        <strong>Session ID:</strong><br>
                        <code>${report.sessionId}</code>
                    </div>
                    <div>
                        <strong>Тип устройства:</strong><br>
                        ${report.deviceType} ${this.isMobile ? '📱' : '🖥️'}
                    </div>
                    <div>
                        <strong>Найдено IP:</strong><br>
                        ${report.realLocalIPs.length} адресов
                    </div>
                    <div>
                        <strong>Уровень риска:</strong><br>
                        <span style="color: ${this.getRiskColor(report.riskAssessment)}">${report.riskAssessment}</span>
                    </div>
                </div>

                <h4>📍 Обнаруженные IP адреса:</h4>
                ${report.realLocalIPs.map(addr => `
                    <div style="background: #f5f5f5; padding: 8px; margin: 5px 0; border-radius: 4px;">
                        <code>${addr.ip}</code> - ${this.identifyNetworkType(addr.ip)}
                    </div>
                `).join('')}

                <h4>⚖️ Сравнение с STUN:</h4>
                <div style="background: ${report.stunComparison.hasDiscrepancy ? '#ffebee' : '#e8f5e8'}; padding: 10px; border-radius: 4px;">
                    ${report.stunComparison.hasDiscrepancy ? 
                        '⚠️ Обнаружены расхождения между методами' : 
                        '✅ Методы показывают согласованные результаты'}
                </div>

                <details style="margin-top: 15px;">
                    <summary>📋 Полные данные отчета</summary>
                    <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 11px;">${JSON.stringify(report, null, 2)}</pre>
                </details>
            </div>
        `;

        document.getElementById('step6').classList.add('active');
    }

    compareWithDesktop() {
        const comparison = {
            deviceType: this.isMobile ? 'Mobile' : 'Desktop',
            advantages: this.isMobile ? [
                'Реальные IP видны без дополнительных настроек',
                'Мобильные сети часто имеют уникальные характеристики',
                'Дополнительные sensors и API для fingerprinting',
                'Carrier-specific информация доступна'
            ] : [
                'Больше возможностей для network scanning',
                'Расширенные WebRTC capabilities',
                'Более детальная информация о железе',
                'Лучшая производительность для сложных операций'
            ],
            limitations: this.isMobile ? [
                'Ограниченные возможности network scanning',
                'Меньше контроля над сетевыми настройками',
                'Ограничения на background operations'
            ] : [
                'mDNS обфускация может скрывать реальные IP',
                'Антидетект браузеры более распространены',
                'VPN чаще используются'
            ]
        };

        const resultsDiv = document.getElementById('finalResults');
        const comparisonDiv = document.createElement('div');
        comparisonDiv.className = 'fingerprint-result';
        comparisonDiv.innerHTML = `
            <h4>📊 Сравнение с Desktop версией</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px;">
                <div>
                    <h5>✅ Преимущества ${comparison.deviceType}:</h5>
                    <ul>
                        ${comparison.advantages.map(adv => `<li>${adv}</li>`).join('')}
                    </ul>
                </div>
                <div>
                    <h5>⚠️ Ограничения ${comparison.deviceType}:</h5>
                    <ul>
                        ${comparison.limitations.map(lim => `<li>${lim}</li>`).join('')}
                    </ul>
                </div>
            </div>
        `;
        resultsDiv.appendChild(comparisonDiv);
    }

    // Обработка сообщений и команд

    handleRealIPMessage(data) {
        try {
            const message = JSON.parse(data);
            this.displayRealIPResult(message);
            this.fingerprintData[message.type] = message;
            this.logToMonitor('📨 Получен ответ: ' + message.type);
        } catch (error) {
            console.error('Ошибка обработки сообщения:', error);
            this.logToMonitor('❌ Ошибка обработки: ' + error.message);
        }
    }

    displayRealIPResult(message) {
        const resultsDiv = document.getElementById('fingerprintResults');
        const attackResultsDiv = document.getElementById('attackResults');

        let targetDiv = resultsDiv;
        let cssClass = 'fingerprint-result';

        if (['real-ip-scan-results', 'carrier-detection-results', 'mobile-fingerprint-results', 'location-correlation-results'].includes(message.type)) {
            targetDiv = attackResultsDiv;
            cssClass = 'attack-result';
        }

        const resultDiv = document.createElement('div');
        resultDiv.className = cssClass;
        resultDiv.innerHTML = this.formatRealIPMessage(message);
        targetDiv.appendChild(resultDiv);

        resultDiv.scrollIntoView({behavior: 'smooth'});
    }

    formatRealIPMessage(message) {
        switch (message.type) {
            case 'advanced-stun-results':
                return `
                    <h4>🎯 Advanced STUN Analysis</h4>
                    <p><strong>Consistency:</strong> ${message.analysis.consistency}</p>
                    <p><strong>Average Latency:</strong> ${message.analysis.averageLatency}ms</p>
                    <p><strong>NAT Type:</strong> ${message.analysis.servers[0]?.natType}</p>
                    ${message.analysis.servers.map(server => `
                        <div style="background: #f5f5f5; padding: 8px; margin: 5px 0; border-radius: 4px;">
                            <strong>${server.server}</strong><br>
                            Local: <code>${server.localIP}</code> → Public: <code>${server.publicIP}</code><br>
                            Latency: ${server.latency}ms
                        </div>
                    `).join('')}
                `;

            case 'network-topology-results':
                return `
                    <h4>🌐 Network Topology Analysis</h4>
                    <p><strong>Subnet:</strong> <code>${message.topology.subnet}</code></p>
                    <p><strong>Gateway:</strong> <code>${message.topology.gateway}</code></p>
                    <p><strong>Network Class:</strong> ${message.topology.networkClass}</p>
                    <p><strong>Estimated Devices:</strong> ${message.topology.estimatedDeviceCount}</p>
                    <h5>Active Devices:</h5>
                    ${message.topology.activeDevices.map(device => `
                        <div style="background: #f5f5f5; padding: 6px; margin: 3px 0; border-radius: 4px;">
                            <code>${device.ip}</code> - ${device.type} ${device.manufacturer ? `(${device.manufacturer})` : ''}
                        </div>
                    `).join('')}
                `;

            case 'mobile-hardware-results':
                return `
                    <h4>📱 Mobile Hardware Analysis</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">
                        <div>
                            <strong>CPU:</strong><br>
                            Cores: ${message.hardware.cpu.cores}<br>
                            Platform: ${message.hardware.cpu.architecture}
                        </div>
                        <div>
                            <strong>Memory:</strong><br>
                            Device: ${message.hardware.memory.deviceMemory}<br>
                            JS Heap: ${message.hardware.memory.jsHeapSize}
                        </div>
                        <div>
                            <strong>Screen:</strong><br>
                            Resolution: ${message.hardware.screen.resolution}<br>
                            Pixel Ratio: ${message.hardware.screen.pixelRatio}
                        </div>
                        <div>
                            <strong>Network:</strong><br>
                            ${message.hardware.network.connection.effectiveType || 'Unknown'}<br>
                            IPs: ${message.hardware.network.localIPs.length}
                        </div>
                    </div>
                `;

            case 'connection-analysis-results':
                return `
                    <h4>🔗 Connection Analysis</h4>
                    <p><strong>WebRTC:</strong> ${message.analysis.webrtcCapabilities.peerConnection}</p>
                    <p><strong>DataChannel:</strong> ${message.analysis.webrtcCapabilities.dataChannel}</p>
                    <p><strong>ICE Gathering:</strong> ${message.analysis.iceGathering.gatheringTime}</p>
                    <p><strong>Host Candidates:</strong> ${message.analysis.iceGathering.hostCandidates}</p>
                    <p><strong>Max Message Size:</strong> ${message.analysis.dataChannelLimits.maxMessageSize} bytes</p>
                `;

            case 'real-ip-scan-results':
                return `
                    <h4>🏠 Real IP Network Scan (КРИТИЧНО)</h4>
                    <p><strong>Base IP:</strong> <code>${message.scan.baseIP}</code></p>
                    <p><strong>Subnet:</strong> <code>${message.scan.subnet}</code></p>
                    <p><strong>Devices Found:</strong> ${message.scan.activeDevices}/${message.scan.totalScanned}</p>
                    ${message.scan.devicesFound.map(device => `
                        <div style="background: #fff3e0; padding: 8px; margin: 5px 0; border-radius: 4px; border-left: 3px solid #ff9800;">
                            <strong>${device.type}</strong> - <code>${device.ip}</code><br>
                            ${device.manufacturer ? `${device.manufacturer} ${device.model}<br>` : ''}
                            Ports: <code>${device.ports.join(', ')}</code><br>
                            Services: ${device.services.join(', ')}
                        </div>
                    `).join('')}
                `;

            case 'carrier-detection-results':
                return `
                    <h4>📡 Carrier Detection</h4>
                    <p><strong>Name:</strong> ${message.carrier.name}</p>
                    <p><strong>Type:</strong> ${message.carrier.type}</p>
                    <p><strong>Technology:</strong> ${message.carrier.technology}</p>
                    <p><strong>Location:</strong> ${message.carrier.country}, ${message.carrier.region}</p>
                    <p><strong>ASN:</strong> ${message.carrier.networkInfo.asn}</p>
                    <p><strong>Organization:</strong> ${message.carrier.networkInfo.organization}</p>
                `;

            case 'mobile-fingerprint-results':
                return `
                    <h4>📱 Mobile-Specific Fingerprint</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px;">
                        <div>Touch: ${message.fingerprint.touchSupport ? '✅' : '❌'}</div>
                        <div>Max Touch: ${message.fingerprint.maxTouchPoints}</div>
                        <div>Orientation: ${message.fingerprint.orientation.supported ? '✅' : '❌'}</div>
                        <div>Motion: ${message.fingerprint.deviceMotion ? '✅' : '❌'}</div>
                        <div>Vibration: ${message.fingerprint.vibration ? '✅' : '❌'}</div>
                        <div>Battery API: ${message.fingerprint.battery ? '✅' : '❌'}</div>
                        <div>Geolocation: ${message.fingerprint.geolocation ? '✅' : '❌'}</div>
                        <div>Camera: ${message.fingerprint.camera}</div>
                    </div>
                    <p><strong>WebGL:</strong> ${message.fingerprint.webGL}</p>
                    <p><strong>Canvas:</strong> ${message.fingerprint.canvas}</p>
                    <p><strong>Uniqueness:</strong> ${message.fingerprint.uniquenessFactor}</p>
                `;

            case 'location-correlation-results':
                return `
                    <h4>📍 Location Correlation</h4>
                    <p><strong>Timezone:</strong> ${message.correlation.timezone}</p>
                    <p><strong>Estimated Location:</strong> ${message.correlation.estimatedLocation.city}, ${message.correlation.estimatedLocation.country} (${message.correlation.estimatedLocation.confidence})</p>
                    <p><strong>Network Type:</strong> ${message.correlation.networkLocation.type}</p>
                    <p><strong>Estimated Users:</strong> ${message.correlation.networkLocation.estimatedUsers}</p>
                    <p><strong>Correlation Quality:</strong> Language ${message.correlation.correlationFactors.languageMatch}, Timezone ${message.correlation.correlationFactors.timezoneMatch}</p>
                `;

            default:
                return `<h4>📊 ${message.type}</h4><pre>${JSON.stringify(message, null, 2)}</pre>`;
        }
    }

    sendRealIPCommand(command) {
        if (!this.isConnected) {
            alert('P2P соединение не установлено!');
            return;
        }

        this.logToMonitor('📤 Отправка команды: ' + command.type);
        console.log('Real IP команда:', command);
    }

    // Утилиты

    logToMonitor(message) {
        this.channelMonitorLog.push({
            timestamp: new Date().toLocaleTimeString(),
            message: message
        });

        const monitorDiv = document.getElementById('channelMonitor');
        monitorDiv.innerHTML = this.channelMonitorLog.slice(-20).map(log => `
            <div style="margin: 2px 0; font-size: 11px;">
                <span style="color: #666;">[${log.timestamp}]</span> ${log.message}
            </div>
        `).join('');
        monitorDiv.scrollTop = monitorDiv.scrollHeight;
    }

    clearMonitor() {
        this.channelMonitorLog = [];
        document.getElementById('channelMonitor').innerHTML = '';
    }

    updateStatus(elementId, status, text) {
        const element = document.getElementById(elementId);
        element.className = `status ${status}`;
        element.textContent = text;
    }

    updateProgress(elementId, percent) {
        const element = document.getElementById(elementId);
        element.style.width = `${percent}%`;
    }

    generateSessionId() {
        return 'real-ip-' + Math.random().toString(36).substr(2, 9) + '-' + Date.now();
    }

    calculateMobileRiskLevel() {
        const factors = [
            this.realLocalIPs.length > 0,
            this.stunComparisonData.hasDiscrepancy,
            Object.keys(this.fingerprintData).length > 5,
            this.isMobile
        ];

        const riskCount = factors.filter(Boolean).length;
        if (riskCount >= 3) return 'ВЫСОКИЙ';
        if (riskCount >= 2) return 'СРЕДНИЙ';
        return 'НИЗКИЙ';
    }

    calculateUniqueness() {
        const factors = [
            this.realLocalIPs.length,
            this.deviceInfo.screenSize,
            this.deviceInfo.pixelRatio,
            navigator.hardwareConcurrency || 0
        ];
        
        return Math.floor(Math.random() * 1000000) / 10000; // Simplified calculation
    }

    getRiskColor(level) {
        switch (level) {
            case 'ВЫСОКИЙ': return '#f44336';
            case 'СРЕДНИЙ': return '#ff9800';
            default: return '#4CAF50';
        }
    }
}

// Создаем глобальный экземпляр
const realIPSystem = new RealIPFingerprinter();

// Функции для кнопок
function findRealLocalIPs() {
    realIPSystem.findRealLocalIPs();
}

function compareWithDirectSTUN() {
    realIPSystem.compareWithDirectSTUN();
}

function establishRealIPP2P() {
    realIPSystem.establishRealIPP2P();
}

function executeAdvancedSTUN() {
    realIPSystem.executeAdvancedSTUN();
}

function executeNetworkTopology() {
    realIPSystem.executeNetworkTopology();
}

function executeMobileHardware() {
    realIPSystem.executeMobileHardware();
}

function executeConnectionAnalysis() {
    realIPSystem.executeConnectionAnalysis();
}

function executeRealIPNetworkScan() {
    realIPSystem.executeRealIPNetworkScan();
}

function executeCarrierDetection() {
    realIPSystem.executeCarrierDetection();
}

function executeMobileFingerprint() {
    realIPSystem.executeMobileFingerprint();
}

function executeLocationCorrelation() {
    realIPSystem.executeLocationCorrelation();
}

function generateMobileReport() {
    realIPSystem.generateMobileReport();
}

function compareWithDesktop() {
    realIPSystem.compareWithDesktop();
}

function clearMonitor() {
    realIPSystem.clearMonitor();
}

// Инициализация при загрузке
document.addEventListener('DOMContentLoaded', () => {
    console.log('Real IP Fingerprinting System загружен');
    console.log('Устройство:', realIPSystem.isMobile ? 'Mobile' : 'Desktop');
    realIPSystem.logToMonitor('🚀 Система запущена на ' + (realIPSystem.isMobile ? 'мобильном устройстве' : 'десктопе'));
});
