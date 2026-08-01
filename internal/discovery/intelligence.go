package discovery

import (
    "strings"

    "lias/internal/database"
)

// InferDeviceType analyzes a merged device observation to guess a friendly
// device type and manufacturer based on hostname, vendor, and services.
func InferDeviceType(obs *database.DeviceObservation) {
    h := strings.ToLower(obs.Hostname + " " + obs.Vendor + " " + obs.Services + " " + obs.OS)

    // 1. Determine Manufacturer
    manufacturer := obs.Vendor
    if manufacturer == "" || manufacturer == "Unknown" {
        if strings.Contains(h, "apple") || strings.Contains(h, "mac") || strings.Contains(h, "iphone") || strings.Contains(h, "ipad") {
            manufacturer = "Apple"
        } else if strings.Contains(h, "samsung") || strings.Contains(h, "galaxy") {
            manufacturer = "Samsung"
        } else if strings.Contains(h, "google") || strings.Contains(h, "pixel") {
            manufacturer = "Google"
        } else if strings.Contains(h, "microsoft") || strings.Contains(h, "windows") {
            manufacturer = "Microsoft"
        } else if strings.Contains(h, "sony") || strings.Contains(h, "playstation") {
            manufacturer = "Sony"
        }
    }
    obs.Manufacturer = manufacturer

    // 2. Determine Device Type
    deviceType := "Generic"
    
    if strings.Contains(h, "iphone") || strings.Contains(h, "android") || strings.Contains(h, "pixel") || strings.Contains(h, "galaxy") || strings.Contains(h, "phone") || strings.Contains(h, "oneplus") {
        deviceType = "Mobile"
    } else if strings.Contains(h, "ipad") || strings.Contains(h, "tablet") {
        deviceType = "Tablet"
    } else if strings.Contains(h, "tv") || strings.Contains(h, "roku") || strings.Contains(h, "appletv") || strings.Contains(h, "fire-tv") || strings.Contains(h, "chromecast") || strings.Contains(h, "smart-tv") {
        deviceType = "TV"
    } else if strings.Contains(h, "printer") || strings.Contains(h, "canon") || strings.Contains(h, "hp ") || strings.Contains(h, "epson") || strings.Contains(h, "brother") || strings.Contains(h, "_ipp") {
        deviceType = "Printer"
    } else if strings.Contains(h, "nest") || strings.Contains(h, "thermostat") || strings.Contains(h, "alexa") || strings.Contains(h, "echo") || strings.Contains(h, "home-assistant") || strings.Contains(h, "smart-plug") || strings.Contains(h, "tuya") || strings.Contains(h, "iot") {
        deviceType = "IoT"
    } else if strings.Contains(h, "mac") || strings.Contains(h, "pc") || strings.Contains(h, "windows") || strings.Contains(h, "linux") || strings.Contains(h, "desktop") || strings.Contains(h, "laptop") || strings.Contains(h, "ubuntu") {
        deviceType = "Computer"
    } else if strings.Contains(h, "nintendo") || strings.Contains(h, "playstation") || strings.Contains(h, "xbox") {
        deviceType = "Gaming"
    } else if strings.Contains(h, "camera") || strings.Contains(h, "hikvision") || strings.Contains(h, "dahua") {
        deviceType = "Camera"
    } else if strings.Contains(h, "nas") || strings.Contains(h, "synology") || strings.Contains(h, "qnap") {
        deviceType = "NAS"
    }

    obs.DeviceType = deviceType
}
