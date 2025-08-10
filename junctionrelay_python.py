#!/usr/bin/env python3
"""
junctionrelay_python.py for Raspberry Pi
Equivalent functionality to the ESP32 version
"""

import json
import time
import base64
import hashlib
import secrets
import requests
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import uuid
import psutil
import subprocess

# Cryptographic imports
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class JunctionRelay:
    def __init__(self, config_file: str = "junction_relay_config.json"):
        self.config_file = Path(config_file)
        self.cloud_base_url = "https://api.junctionrelay.com"
        
        # State variables
        self.jwt = ""
        self.refresh_token = ""
        self.device_id = ""
        self.registered = False
        self.public_key = None  # Will store the peer's public key
        self.jwt_expires_at = 0
        self.last_token_refresh = 0
        self.last_report = 0
        self.sensors = {}
        
        # Constants (matching ESP32 version)
        self.JWT_REFRESH_BUFFER = 300  # 5 minutes in seconds
        self.TOKEN_REFRESH_INTERVAL = 3600  # 1 hour in seconds
        self.HEALTH_REPORT_INTERVAL = 60  # 60 seconds
        
        # Background thread control
        self.running = False
        self.background_thread = None
        
        # Load existing configuration
        self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                self.jwt = config.get("jwt", "")
                self.refresh_token = config.get("refresh_token", "")
                self.device_id = config.get("device_id", "")
                self.jwt_expires_at = config.get("jwt_expires_at", 0)
                self.last_token_refresh = config.get("last_token_refresh", 0)
                
                # Load public key if available
                if "public_key_b64" in config:
                    self.set_public_key_from_b64(config["public_key_b64"])
                
                self.registered = bool(self.jwt and self.public_key)
                
                if self.registered:
                    print("✅ Device registered")
                    if self.refresh_token and self.device_id:
                        print("📱 Found stored refresh token")
                        print(f"🆔 Device ID: {self.device_id}")
                    else:
                        print("ℹ️ No stored tokens found - will need fresh registration")
                else:
                    print("⏳ Need registration token")
                    
            except Exception as e:
                print(f"❌ Error loading config: {e}")
                
    def save_config(self):
        """Save configuration to file"""
        try:
            config = {
                "jwt": self.jwt,
                "refresh_token": self.refresh_token,
                "device_id": self.device_id,
                "jwt_expires_at": self.jwt_expires_at,
                "last_token_refresh": self.last_token_refresh,
            }
            
            # Save public key if available
            if self.public_key:
                # Convert public key to base64 for storage
                public_bytes = self.public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                config["public_key_b64"] = base64.b64encode(public_bytes).decode()
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
                
            print("💾 Configuration saved")
            
        except Exception as e:
            print(f"❌ Error saving config: {e}")
            
    def clear_stored_tokens(self):
        """Clear stored tokens and reset registration state"""
        self.refresh_token = ""
        self.device_id = ""
        self.jwt_expires_at = 0
        self.last_token_refresh = 0
        self.jwt = ""
        self.registered = False
        self.save_config()
        print("🗑️ Cleared stored tokens")
        
    def get_device_id(self) -> str:
        """Get unique device identifier (MAC address equivalent)"""
        if not self.device_id:
            # Try to get MAC address, fallback to UUID
            try:
                # Get the first available network interface MAC
                import psutil
                for interface, addrs in psutil.net_if_addrs().items():
                    if interface != 'lo':  # Skip loopback
                        for addr in addrs:
                            if addr.family == psutil.AF_LINK:
                                self.device_id = addr.address.upper()
                                break
                        if self.device_id:
                            break
            except:
                pass
                
            # Fallback to UUID if MAC not available
            if not self.device_id:
                self.device_id = str(uuid.getnode())
                
        return self.device_id
        
    def set_public_key_from_b64(self, b64_key: str) -> bool:
        """Set the peer's public key from base64 string"""
        try:
            # Clean the input
            cleaned = b64_key.strip().replace('\n', '').replace('\r', '').replace(' ', '')
            
            print(f"Cleaned base64 public key length: {len(cleaned)}")
            
            # Decode base64
            decoded = base64.b64decode(cleaned)
            print(f"Decoded public key length: {len(decoded)}, first byte=0x{decoded[0]:02X}")
            
            # Handle both compressed and uncompressed formats
            if len(decoded) == 65 and decoded[0] == 0x04:
                # Already uncompressed
                key_bytes = decoded
            elif len(decoded) == 33 and decoded[0] in [0x02, 0x03]:
                # Compressed - need to decompress
                print("🔄 Decompressing compressed public key...")
                key_bytes = self._decompress_public_key(decoded)
                if not key_bytes:
                    print("❌ Failed to decompress compressed public key")
                    return False
            else:
                print("❌ Invalid P-256 public key format")
                return False
                
            # Load the key using cryptography library
            self.public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), key_bytes
            )
            
            print("✅ P-256 public key set and validated")
            return True
            
        except Exception as e:
            print(f"❌ Error setting public key: {e}")
            return False
            
    def _decompress_public_key(self, compressed_bytes: bytes) -> Optional[bytes]:
        """Decompress a compressed P-256 public key"""
        try:
            # Use the cryptography library to handle decompression
            compressed_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), compressed_bytes
            )
            
            # Convert back to uncompressed format
            uncompressed = compressed_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            print(f"DEBUG: Decompressed key length: {len(uncompressed)}")
            return uncompressed
            
        except Exception as e:
            print(f"DEBUG: Decompression failed: {e}")
            return None
            
    def set_token(self, token: str):
        """Set registration token and parse it"""
        if not self.registered and token:
            try:
                token_data = json.loads(token)
                if all(key in token_data for key in ["publicKey", "deviceName", "token"]):
                    print("🔑 Registration token validated")
                    print(f"Device: {token_data['deviceName']}")
                    
                    if self.set_public_key_from_b64(token_data["publicKey"]):
                        self.register_device(token_data)
                    
            except json.JSONDecodeError:
                print("❌ Invalid JSON format")
                
    def register_device(self, token_data: Dict[str, Any]):
        """Register device with the cloud service"""
        try:
            device_id = self.get_device_id()
            
            payload = {
                "registrationToken": token_data["token"],
                "actualDeviceId": device_id,
                "deviceName": token_data["deviceName"]
            }
            
            print("📡 Registering device...")
            
            response = requests.post(
                f"{self.cloud_base_url}/cloud/devices/register",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if "deviceJwt" in result:
                    self.jwt = result["deviceJwt"]
                    self.registered = True
                    
                    # Extract and store refresh token
                    if "refreshToken" in result:
                        self.refresh_token = result["refreshToken"]
                        self.device_id = device_id
                        
                        # Set JWT expiry (8 hours from now)
                        self.jwt_expires_at = time.time() + (8 * 60 * 60)
                        self.last_token_refresh = time.time()
                        
                        print("✅ Device registered with refresh token!")
                    else:
                        print("✅ Device registered!")
                        
                    self.save_config()
                    
            else:
                print(f"❌ Registration failed: {response.status_code}")
                print(f"Response: {response.text}")
                
        except Exception as e:
            print(f"❌ Registration error: {e}")
            
    def check_and_refresh_token(self):
        """Check if JWT token needs refresh and refresh if necessary"""
        if not self.refresh_token or not self.device_id:
            return
            
        current_time = time.time()
        
        # Check if 1 hour has passed since last refresh
        if current_time - self.last_token_refresh < self.TOKEN_REFRESH_INTERVAL:
            return
            
        # Also check if JWT is near expiry
        near_expiry = (self.jwt_expires_at > 0 and 
                      current_time + self.JWT_REFRESH_BUFFER >= self.jwt_expires_at)
        interval_reached = (current_time - self.last_token_refresh >= self.TOKEN_REFRESH_INTERVAL)
        
        if interval_reached or near_expiry:
            print("🔄 JWT token refresh triggered")
            if interval_reached:
                print("  📅 Reason: 1-hour interval reached")
            if near_expiry:
                print("  ⏰ Reason: Token near expiry")
                
            self.last_token_refresh = current_time
            
            if not self.refresh_device_token():
                self.handle_token_refresh_failure()
            else:
                self.save_config()
                
    def refresh_device_token(self) -> bool:
        """Refresh the JWT token using refresh token"""
        try:
            payload = {
                "RefreshToken": self.refresh_token,
                "DeviceId": self.device_id
            }
            
            print("📤 Sending token refresh request")
            
            response = requests.post(
                f"{self.cloud_base_url}/cloud/devices/refresh",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                print("✅ Token refresh successful")
                
                if result.get("success") and "token" in result:
                    self.jwt = result["token"]
                    
                    # Parse expiry time if provided
                    if "expiresAt" in result:
                        # Simple parsing - in production you'd want proper ISO8601 parsing
                        self.jwt_expires_at = time.time() + (8 * 60 * 60)  # 8 hours default
                        print(f"⏰ Token expires at: {result['expiresAt']}")
                    else:
                        self.jwt_expires_at = time.time() + (8 * 60 * 60)
                        print("⏰ Using default 8-hour expiry")
                        
                    return True
                else:
                    print("❌ Failed to parse token refresh response or success=false")
                    return False
                    
            else:
                print(f"❌ Token refresh failed with code: {response.status_code}")
                print(f"📨 Error response: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Token refresh error: {e}")
            return False
            
    def handle_token_refresh_failure(self):
        """Handle token refresh failure by clearing tokens and requiring re-registration"""
        print("⚠️ Token refresh failed - clearing stored tokens")
        self.clear_stored_tokens()
        print("🔄 Device will need to re-register")
        
    def encrypt_data(self, data: str) -> Optional[str]:
        """Encrypt data using ECDH + AES-GCM (matching ESP32 implementation)"""
        try:
            if not self.public_key:
                print("❌ No public key available for encryption")
                return None
                
            # 1. Generate ephemeral key pair
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            
            # 2. Perform ECDH to get shared secret
            shared_key = private_key.exchange(ec.ECDH(), self.public_key)
            
            # 3. Use shared secret as AES key (first 32 bytes)
            aes_key = shared_key[:32]
            
            # 4. Generate random IV (12 bytes for GCM)
            iv = secrets.token_bytes(12)
            
            # 5. Encrypt using AES-GCM
            aesgcm = AESGCM(aes_key)
            ciphertext_with_tag = aesgcm.encrypt(iv, data.encode('utf-8'), None)
            
            # 6. Get ephemeral public key in compressed format
            ephemeral_public = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint
            )
            
            # 7. Pack: ephemeral_public || iv || ciphertext_with_tag
            packed_data = ephemeral_public + iv + ciphertext_with_tag
            
            # 8. Base64 encode
            return base64.b64encode(packed_data).decode('ascii')
            
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            return None
            
    def add_sensor(self, key: str, value: str):
        """Add sensor data"""
        self.sensors[key] = value
        
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics similar to ESP32 version"""
        try:
            # Get uptime
            with open('/proc/uptime', 'r') as f:
                uptime = int(float(f.readline().split()[0]))
                
            # Get memory info
            memory = psutil.virtual_memory()
            
            # Get CPU temperature (Raspberry Pi specific)
            cpu_temp = None
            try:
                result = subprocess.run(['vcgencmd', 'measure_temp'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    temp_str = result.stdout.strip()
                    cpu_temp = float(temp_str.replace('temp=', '').replace("'C", ''))
            except:
                pass
                
            stats = {
                "uptime": uptime,
                "freeHeap": memory.available,
                "totalMemory": memory.total,
                "memoryUsage": memory.percent,
                "cpuUsage": psutil.cpu_percent(interval=1)
            }
            
            if cpu_temp is not None:
                stats["cpuTemp"] = cpu_temp
                
            return stats
            
        except Exception as e:
            print(f"❌ Error getting system stats: {e}")
            return {"uptime": int(time.time()), "error": str(e)}
            
    def send_health(self):
        """Send health report to cloud service"""
        try:
            if not self.registered or not self.jwt:
                return
                
            # Prepare health data
            health_data = self.get_system_stats()
            
            # Add sensor data
            health_data.update(self.sensors)
            
            # Convert to JSON string
            data_str = json.dumps(health_data, separators=(',', ':'))
            
            print(f"DEBUG: Raw health data: {data_str}")
            
            # Encrypt the data
            encrypted_data = self.encrypt_data(data_str)
            if not encrypted_data:
                print("❌ Encryption failed")
                return
                
            print(f"DEBUG: Encrypted data length: {len(encrypted_data)}")
            
            # Prepare payload
            payload = {
                "Status": "online",
                "SensorData": encrypted_data
            }
            
            print(f"DEBUG: HTTP payload length: {len(json.dumps(payload))}")
            
            # Send request
            response = requests.post(
                f"{self.cloud_base_url}/cloud/devices/health",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.jwt}",
                    "Content-Type": "application/json"
                },
                timeout=30
            )
            
            if response.status_code == 200:
                print("✅ Health sent")
            else:
                print(f"❌ Health failed: {response.status_code}")
                print(f"DEBUG: Error response: {response.text}")
                
            # Clear sensors after sending
            self.sensors.clear()
            
        except Exception as e:
            print(f"❌ Health send error: {e}")
            
    def wait_for_token(self):
        """Wait for user to input registration token"""
        print("📋 Paste registration token (JSON) and press Enter:")
        try:
            token = input().strip()
            if token.startswith('{') and token.endswith('}'):
                self.set_token(token)
            else:
                print("❌ Invalid JSON format")
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            return False
        return True
        
    def handle(self):
        """Main handling method (equivalent to ESP32 handle())"""
        if not self.registered:
            return self.wait_for_token()
            
        # Check if we need to refresh token
        self.check_and_refresh_token()
        
        # Send health report every minute
        current_time = time.time()
        if current_time - self.last_report > self.HEALTH_REPORT_INTERVAL:
            self.send_health()
            self.last_report = current_time
            
        return True
        
    def start_background_service(self):
        """Start background service thread"""
        if self.running:
            return
            
        self.running = True
        self.background_thread = threading.Thread(target=self._background_loop, daemon=True)
        self.background_thread.start()
        print("🚀 Background service started")
        
    def stop_background_service(self):
        """Stop background service"""
        self.running = False
        if self.background_thread:
            self.background_thread.join()
        print("⏹️ Background service stopped")
        
    def _background_loop(self):
        """Background loop for continuous operation"""
        while self.running:
            try:
                if not self.handle():
                    break
                time.sleep(1)  # Small delay to prevent busy waiting
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"❌ Background loop error: {e}")
                time.sleep(5)  # Wait before retrying


def main():
    """Main function for standalone operation"""
    print("🚀 JunctionRelay Python Starting...")
    
    # Initialize JunctionRelay
    relay = JunctionRelay()
    
    print("📊 Device ready")
    
    try:
        # Add some demo sensor data periodically
        def add_demo_sensors():
            import random
            relay.add_sensor("temperature", f"{random.uniform(20.0, 30.0):.1f}")
            relay.add_sensor("humidity", str(random.randint(40, 80)))
            relay.add_sensor("status", "online")
            
        last_sensor_time = 0
        
        # Main loop
        while True:
            if not relay.handle():
                break
                
            # Add demo sensors every 30 seconds
            current_time = time.time()
            if current_time - last_sensor_time > 30:
                add_demo_sensors()
                last_sensor_time = current_time
                
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Main loop error: {e}")
    finally:
        relay.stop_background_service()


if __name__ == "__main__":
    main()