// +build !windows

package sasl

func ntlm(spn string) Mechanism {
	return Mechanism{
		Name: "GSS-SPGENO",
		Start: func(m *Negotiator) (bool, []byte, interface{}, error) {
			return false, nil, nil, nil
		},
		Next: func(m *Negotiator, challenge []byte, data interface{}) (more bool, resp []byte, cache interface{}, err error) {
			if challenge == nil || len(challenge) == 0 {
				return more, resp, cache, ErrInvalidChallenge
			}

			state := m.State()

			switch state & StepMask {
			case AuthTextSent:
			case ResponseSent:
			case ValidServerResponse:
			}
			return
		},
	}
}
