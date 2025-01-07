import ping3
import requests
import logging

def get_location_info(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        if response.status_code == 200:
            ipinfo_data = response.json()
            return {
                "City": ipinfo_data.get("city"),
                "Region": ipinfo_data.get("region"),
                "Country": ipinfo_data.get("country"),
                # "Latitude": ipinfo_data.get("loc").split(",")[0] if ipinfo_data.get("loc") else None,
                # "Longitude": ipinfo_data.get("loc").split(",")[1] if ipinfo_data.get("loc") else None,
            }
        else:
            return "Location lookup failed"
    except Exception as e:
        logging.error(f"Location lookup failed: {e}")
        return {}

def get_ping_info(ip_address):
    try:
        latency = ping3.ping(ip_address, timeout=5)  # Ping with a 5-second timeout
        if latency is not None:
            return {"status": "success", "latency": f"{latency:.2f} ms"}
        else:
            return {"status": "failed", "error": "Request timed out"}
    except Exception as e:
        return {"status": "failed", "error": f"Ping error: {e}"}


def Locate_and_Ping(target_IP):
    location_info = get_location_info(target_IP)
    ping_info = get_ping_info(target_IP)

    return {
        "location_info": location_info,
        "ping_info": ping_info
    }
