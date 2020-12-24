package server

import (
	"time"
)

type ServerProperties struct {
	Name      string
	StartedAt time.Time
}

func NewServerProperties(name string) ServerProperties {
	return ServerProperties{
		Name:      name,
		StartedAt: time.Now(),
	}
}

func (props ServerProperties) Uptime() time.Duration {
	return time.Now().Sub(props.StartedAt)
}
