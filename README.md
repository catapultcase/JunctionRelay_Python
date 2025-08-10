# JunctionRelay Python Client for Raspberry Pi

A Python implementation of the JunctionRelay device client, designed to run on Raspberry Pi and other Linux systems. This client provides secure, encrypted communication with the JunctionRelay cloud platform for IoT device management and monitoring.

## Features

- 🔐 **Secure Communication**: End-to-end encryption using ECDH key exchange and AES-GCM
- 🔄 **Automatic Token Refresh**: JWT tokens are automatically refreshed to maintain connectivity
- 📊 **System Monitoring**: Collects and reports system statistics (CPU, memory, temperature)
- 💾 **Persistent Configuration**: Device settings and tokens are stored locally
- 🚀 **Background Service**: Can run as a systemd service for continuous operation
- 📡 **Health Reporting**: Regular encrypted health reports to the cloud platform
- 🔧 **Easy Registration**: Simple token-based device registration process

## Requirements

- Raspberry Pi (or any Linux system with Python 3.7+)
- Internet connection
- JunctionRelay account and registration token

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/catapultcase/JunctionRelay_Python.git
cd JunctionRelay_Python
```

### 2. Run Setup Script

```bash
chmod +x setup_raspberry_pi.sh
./setup_raspberry_pi.sh
```

This will:
- Install required system dependencies
- Create a Python virtual environment
- Install Python packages

### 3. Run the Client

```bash
source junction_relay_env/bin/activate
python3 junctionrelay_python.py
```

### 4. Register Your Device

When first running, you'll be prompted to paste your registration token:

```
📋 Paste registration token (JSON) and press Enter:
```

Paste the JSON token you received from your JunctionRelay dashboard and press Enter.

## Installation as a System Service

To run JunctionRelay automatically on boot:

### 1. Copy Service File

```bash
sudo cp junctionrelay.service /etc/systemd/system/
```

### 2. Update Service File Paths

Edit `/etc/systemd/system/junctionrelay.service` and adjust paths if needed:

```ini
WorkingDirectory=/home/pi/JunctionRelay_Python
ExecStart=/home/pi/JunctionRelay_Python/junction_relay_env/bin/python /home/pi/JunctionRelay_Python/junction_relay.py
```

### 3. Enable and Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable junctionrelay
sudo systemctl start junctionrelay
```

### 4. Check Service Status

```bash
sudo systemctl status junctionrelay
```

### 5. View Logs

```bash
sudo journalctl -u junctionrelay -f
```

## Configuration

Configuration is automatically saved to `junction_relay_config.json` in the same directory as the script. This includes:

- Device JWT token
- Refresh token
- Device ID
- Public key
- Token expiry information

## Custom Sensor Data

You can add custom sensor readings using the `add_sensor()` method:

```python
relay = JunctionRelay()
relay.add_sensor("temperature", "23.5")
relay.add_sensor("humidity", "65")
relay.add_sensor("custom_sensor", "some_value")
```

## System Statistics

The client automatically reports these system statistics:

- **Uptime**: System uptime in seconds
- **Memory Usage**: Available and total memory
- **CPU Usage**: Current CPU usage percentage
- **CPU Temperature**: CPU temperature (Raspberry Pi specific)

## Security

- All sensor data and system statistics are encrypted using ECDH + AES-GCM
- JWT tokens are automatically refreshed every hour
- Failed token refreshes trigger automatic re-registration
- Secure random number generation for cryptographic operations