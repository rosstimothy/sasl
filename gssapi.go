// +build !windows

package sasl

import (
	"github.com/sirupsen/logrus"
)

func gssapi(spn string) Mechanism {
	return Mechanism{
		Name: "GSSAPI",
		Start: func(m *Negotiator) (bool, []byte, interface{}, error) {
			return false, nil, nil, nil
		},
		Next: func(m *Negotiator, challenge []byte, data interface{}) (more bool, resp []byte, cache interface{}, err error) {
			if challenge == nil || len(challenge) == 0 {
				return more, resp, cache, ErrInvalidChallenge
			}

			state := m.State()

			logrus.WithField("state", state&StepMask).Info("Next")
			switch state & StepMask {
			case AuthTextSent:
			case ResponseSent:
			case ValidServerResponse:
			}
			return
		},
	}
}
