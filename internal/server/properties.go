package server

import (
	"time"
)

type ServerProperties struct {
	StartedAt time.Time
}

func (props ServerProperties) Uptime() time.Duration {
	return time.Now().Sub(props.StartedAt)
}
