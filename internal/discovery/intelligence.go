package discovery

import (
    "strings"

    "lias/internal/database"
)

// InferDeviceType analyzes a merged device observation to guess a friendly
// device type and manufacturer based on hostname, vendor, and services.
func InferDeviceType(obs *database.DeviceObservation) {
    // Combine all metadata into a single lowercase string for easy searching
    h := strings.ToLower(obs.Hostname + " " + obs.Vendor + " " + obs.Services + " " + obs.OS + " " + obs.Manufacturer)

    // 1. Determine Manufacturer (if not already set by Nmap)
    manufacturer := obs.Vendor
    if manufacturer == "" || manufacturer == "Unknown" {
        if strings.Contains(h, "apple") || strings.Contains(h, "mac") || strings.Contains(h, "iphone") || strings.Contains(h, "ipad") || strings.Contains(h, "airplay") {
            manufacturer = "Apple"
        } else if strings.Contains(h, "samsung") || strings.Contains(h, "galaxy") {
            manufacturer = "Samsung"
        } else if strings.Contains(h, "google") || strings.Contains(h, "pixel") || strings.Contains(h, "chromecast") {
            manufacturer = "Google"
        } else if strings.Contains(h, "microsoft") || strings.Contains(h, "windows") {
            manufacturer = "Microsoft"
        } else if strings.Contains(h, "sony") || strings.Contains(h, "playstation") {
            manufacturer = "Sony"
        } else if strings.Contains(h, "espressif") || strings.Contains(h, "tuya") {
            manufacturer = "Espressif (IoT)"
        }
    }
    obs.Manufacturer = manufacturer

    // 2. Determine Device Type
    deviceType := "Generic"
    
    // Check services first (most reliable for IoT/TVs)
    if strings.Contains(h, "_airplay._tcp") || strings.Contains(h, "_companion-link._tcp") {
        deviceType = "Apple Device"
    } else if strings.Contains(h, "_googlecast._tcp") || strings.Contains(h, "chromecast") {
        deviceType = "Google Cast"
    } else if strings.Contains(h, "_ipp._tcp") || strings.Contains(h, "_printer._tcp") || strings.Contains(h, "printer") || strings.Contains(h, "canon") || strings.Contains(h, "epson") {
        deviceType = "Printer"
    } else if strings.Contains(h, "_smb._tcp") || strings.Contains(h, "nbns") || strings.Contains(h, "windows") {
        deviceType = "Computer"
    } else if strings.Contains(h, "_http._tcp") || strings.Contains(h, "ssdp") {
        // Could be a TV, Router, or IoT
        if strings.Contains(h, "tv") || strings.Contains(h, "roku") || strings.Contains(h, "smart") {
            deviceType = "TV"
        } else if strings.Contains(h, "router") || strings.Contains(h, "gateway") {
            deviceType = "Router"
        } else {
            deviceType = "IoT Device"
        }
    }

    // Fallback to hostname guessing if service detection failed
    if deviceType == "Generic" {
        if strings.Contains(h, "iphone") || strings.Contains(h, "android") || strings.Contains(h, "pixel") || strings.Contains(h, "galaxy") || strings.Contains(h, "phone") {
            deviceType = "Mobile"
        } else if strings.Contains(h, "ipad") || strings.Contains(h, "tablet") {
            deviceType = "Tablet"
        } else if strings.Contains(h, "tv") || strings.Contains(h, "roku") || strings.Contains(h, "appletv") || strings.Contains(h, "fire-tv") {
            deviceType = "TV"
        } else if strings.Contains(h, "mac") || strings.Contains(h, "pc") || strings.Contains(h, "linux") || strings.Contains(h, "desktop") || strings.Contains(h, "laptop") || strings.Contains(h, "ubuntu") {
            deviceType = "Computer"
        } else if strings.Contains(h, "nintendo") || strings.Contains(h, "playstation") || strings.Contains(h, "xbox") {
            deviceType = "Gaming"
        } else if strings.Contains(h, "camera") || strings.Contains(h, "hikvision") || strings.Contains(h, "dahua") {
            deviceType = "Camera"
        } else if strings.Contains(h, "nas") || strings.Contains(h, "synology") || strings.Contains(h, "qnap") {
            deviceType = "NAS"
        } else if strings.Contains(h, "nest") || strings.Contains(h, "thermostat") || strings.Contains(h, "alexa") || strings.Contains(h, "echo") || strings.Contains(h, "home-assistant") {
            deviceType = "IoT"
        }
    }

    obs.DeviceType = deviceType
}
