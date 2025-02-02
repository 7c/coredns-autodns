package autodns

import (
	"strings"
)

func UniformZone(zone string) string {
	zone = strings.TrimSpace(zone)
	zone = strings.ToLower(zone)
	zone = strings.TrimSuffix(zone, ".")
	zone = zone + "."
	return zone
}
