package autodns

import (
	"net"
	"strconv"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
)

var logger = log.NewWithPlugin("autodns")

func init() {
	caddy.RegisterPlugin("autodns", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	r, err := redisSetup(c)
	if err != nil {
		return plugin.Error("autodns", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		r.Next = next
		return r
	})

	if r.Verbose {
		logger.Info("Configuration:")
		logger.Info("\tHost: ", r.redisAddress)
		logger.Info("\tPassword: ", r.redisPassword)
		logger.Info("\tConnect Timeout: ", r.connectTimeout)
		logger.Info("\tRead Timeout: ", r.readTimeout)
		logger.Info("\tTTL: ", r.Ttl)
		// logger.Info("\tACL Networks: ", r.AclNetworks)
	}

	// config := dnsserver.GetConfig(c)

	// lets check if the acl plugin is loaded
	// c.OnFirstStartup(func() error {
	// 	if config.Handler("acl") == nil {
	// 		return errors.New("you should always use acl plugin with autodns plugins")
	// 	}
	// 	logger.Info("acl plugin found")
	// 	return nil
	// })
	return nil
}

func redisSetup(c *caddy.Controller) (*Autodns, error) {
	autodns := Autodns{
		keyPrefix: "",
		keySuffix: "",
		Ttl:       300,
		Verbose:   false,
	}
	var (
		err error
	)

	for c.Next() {
		if c.NextBlock() {
			for {
				switch c.Val() {
				case "address":
					if !c.NextArg() {
						return &Autodns{}, c.ArgErr()
					}
					autodns.redisAddress = c.Val()
				case "password":
					if !c.NextArg() {
						return &Autodns{}, c.ArgErr()
					}
					autodns.redisPassword = c.Val()
				case "prefix":
					if !c.NextArg() {
						return &Autodns{}, c.ArgErr()
					}
					autodns.keyPrefix = c.Val()
				case "suffix":
					if !c.NextArg() {
						return &Autodns{}, c.ArgErr()
					}
					autodns.keySuffix = c.Val()
				case "connect_timeout":
					if !c.NextArg() {
						return &Autodns{}, c.ArgErr()
					}
					autodns.connectTimeout, err = strconv.Atoi(c.Val())
					if err != nil {
						autodns.connectTimeout = 0
					}
				case "read_timeout":
					if !c.NextArg() {
						return &Autodns{}, c.ArgErr()
					}
					autodns.readTimeout, err = strconv.Atoi(c.Val())
					if err != nil {
						autodns.readTimeout = 0
					}
				case "ttl":
					if !c.NextArg() {
						return &Autodns{}, c.ArgErr()
					}
					var val int
					val, err = strconv.Atoi(c.Val())
					if err != nil {
						val = defaultTtl
					}
					autodns.Ttl = uint32(val)
				case "autocreate":
					if !c.NextArg() {
						return &Autodns{}, c.ArgErr()
					}
					cVal := strings.TrimSpace(c.Val())
					autodns.AutoCreate = append(autodns.AutoCreate, cVal)
					logger.Info("Auto create enabled for: ", cVal)
				case "verbose":
					autodns.Verbose = true
					logger.Info("Verbose mode enabled")
				case "register.network":
					// which networks are allowed to register
					if !c.NextArg() {
						return &Autodns{}, c.ArgErr()
					}
					cVal := strings.TrimSpace(c.Val())
					ips := strings.Split(cVal, " ")

					for _, ip := range ips {
						ip = strings.TrimSpace(ip)
						_, ipnet, err := net.ParseCIDR(ip)
						if err != nil {
							logger.Info("Error: ", err)
							return &Autodns{}, c.ArgErr()
						}
						logger.Info("Register Network: ", ip)
						autodns.RegisterNetworks = append(autodns.RegisterNetworks, *ipnet)
					}
				case "register.deny":
					if !c.NextArg() {
						return &Autodns{}, c.ArgErr()
					}
					cVal := strings.TrimSpace(c.Val())
					cVal = strings.ToLower(cVal)
					autodns.RegisterDeny = append(autodns.RegisterDeny, cVal)
					logger.Info("Register Deny: ", cVal)
				default:
					if c.Val() != "}" {
						return &Autodns{}, c.Errf("unknown configuration property '%s'", c.Val())
					}
				}

				if !c.Next() {
					break
				}
			}

		}

		autodns.Connect()
		autodns.LoadZones()

		return &autodns, nil
	}
	return &Autodns{}, nil
}
